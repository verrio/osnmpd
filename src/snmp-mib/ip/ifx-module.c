/*
 * This file is part of the osnmpd distribution (https://github.com/verrio/osnmpd).
 * Copyright (C) 2016 Olivier Verriest
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/utsname.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/ip/if-cache.h"
#include "snmp-mib/ip/ip-cache.h"
#include "snmp-mib/ip/ip-address-cache.h"
#include "snmp-mib/ip/ifx-module.h"

enum IFXStastMIB {
    IF_X_TABLE = 1,
    IF_STACK_TABLE = 2,
    IF_TEST_TABLE = 3,
    IF_RCV_ADDRESS_TABLE = 4,
    IF_TABLE_LAST_CHANGE = 5,
    IF_STACK_LAST_CHANGE = 6
};

enum IFXTableColumns {
    IF_NAME = 1,
    IF_IN_MULTICAST_PKTS = 2,
    IF_IN_BROADCAST_PKTS = 3,
    IF_OUT_MULTICAST_PKTS = 4,
    IF_OUT_BROADCAST_PKTS = 5,
    IF_HC_IN_OCTETS = 6,
    IF_HC_IN_UCAST_PKTS = 7,
    IF_HC_IN_MULTICAST_PKTS = 8,
    IF_HC_IN_BROADCAST_PKTS = 9,
    IF_HC_OUT_OCTETS = 10,
    IF_HC_OUT_UCAST_PKTS = 11,
    IF_HC_OUT_MULTICAST_PKTS = 12,
    IF_HC_OUT_BROADCAST_PKTS = 13,
    IF_LINK_UP_DOWN_TRAP_ENABLE = 14,
    IF_HIGH_SPEED = 15,
    IF_PROMISCUOUS_MODE = 16,
    IF_CONNECTOR_PRESENT = 17,
    IF_ALIAS = 18,
    IF_COUNTER_DISCONTINUITY_TIME = 19
};

enum IFStackTableColumns {
    IF_STACK_HIGHER_LAYER = 1,
    IF_STACK_LOWER_LAYER = 2,
    IF_STACK_STATUS = 3
};

enum IFTestTableColumns {
    IF_TEST_ID = 1,
    IF_TEST_STATUS = 2,
    IF_TEST_TYPE = 3,
    IF_TEST_RESULT = 4,
    IF_TEST_CODE = 5,
    IF_TEST_OWNER = 6
};

enum IFRcvAddressTableColumns {
    IF_RCV_ADDRESS_ADDRESS = 1,
    IF_RCV_ADDRESS_STATUS = 2,
    IF_RCV_ADDRESS_TYPE = 3
};

static int has_physical_iface(IfaceEntry *iface) {
    switch (iface->type) {
        case IF_TYPE_PPP:
        case IF_TYPE_SOFTWARE_LOOP_BACK:
        case IF_TYPE_IEEE_802_11:
        case IF_TYPE_STACK_TO_STACK:
        case IF_TYPE_VIRTUAL_IP_ADDRESS:
        case IF_TYPE_TUNNEL:
        case IF_TYPE_MPLS_TUNNEL:
        case IF_TYPE_VMWARE_VIRTUAL_NIC:
        case IF_TYPE_VMWARE_NIC_TEAM: {
            return 2; /* false */
        }

        default: {
            return 1; /* true */
        }
    }
}

static IfaceEntry *get_iface_entry(const SubOID *row,
        const size_t row_len, const int next_row)
{
    int index = 0;
    if (row_len > 1) {
        if (next_row) {
            index = row[0];
        } else {
            return NULL;
        }
    } else if (row_len > 0) {
        index = row[0];
    }

    for (IfaceEntry *cur = get_iface_list(); cur != NULL; cur = cur->next) {
        if (cur->id > index) {
            return next_row ? cur : NULL;
        } else if (cur->id == index && !next_row) {
            return cur;
        }
    }

    return NULL;
}

static IfaceEntry *get_iface_addr_entry(SubOID *row, size_t row_len, int next_row)
{
    int iface = row_len < 1 ? 0 : row[0];
    IfaceEntry *entry;

    for (entry = get_iface_list(); entry != NULL; entry = entry->next) {
        if (entry->id >= iface) {
            break;
        }
    }

    if (next_row) {
        if (iface == entry->id) {
            switch (cmp_index_to_array(entry->address,
                    entry->address_len, &row[1], row_len - 1)) {
                case 0:
                case 1: {
                    entry = entry->next;
                }
            }
        }
    } else if (row_len < 2 || row[0] != entry->id
        || row[1] != entry->address_len) {
        return NULL;
    } else if (cmp_index_to_array(entry->address,
        entry->address_len, &row[1], row_len - 1)) {
        return NULL;
    }

    return entry;
}

static SnmpErrorStatus get_ifx_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    IfaceEntry *iface = get_iface_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, iface);

    switch (column) {
        case IF_NAME: {
            SET_OCTET_STRING_RESULT(binding, strndup(iface->iface_name, IFNAMSIZ),
                strnlen(iface->iface_name, IFNAMSIZ));
            break;
        }

        case IF_IN_MULTICAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.in_mcast_pkts));
            break;
        }

        case IF_IN_BROADCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.in_bcast_pkts));
            break;
        }

        case IF_OUT_MULTICAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.out_mcast_pkts));
            break;
        }

        case IF_OUT_BROADCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.out_bcast_pkts));
            break;
        }

        case IF_HC_IN_OCTETS: {
            SET_UNSIGNED64_BIND(binding, iface->mac_stats.in_octets);
            break;
        }

        case IF_HC_IN_UCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, iface->mac_stats.in_ucast_pkts);
            break;
        }

        case IF_HC_IN_MULTICAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, iface->mac_stats.in_mcast_pkts);
            break;
        }

        case IF_HC_IN_BROADCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, iface->mac_stats.in_bcast_pkts);
            break;
        }

        case IF_HC_OUT_OCTETS: {
            SET_UNSIGNED64_BIND(binding, iface->mac_stats.out_octets);
            break;
        }

        case IF_HC_OUT_UCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, iface->mac_stats.out_ucast_pkts);
            break;
        }

        case IF_HC_OUT_MULTICAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, iface->mac_stats.out_mcast_pkts);
            break;
        }

        case IF_HC_OUT_BROADCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, iface->mac_stats.out_bcast_pkts);
            break;
        }

        case IF_LINK_UP_DOWN_TRAP_ENABLE: {
            SET_INTEGER_BIND(binding, 2); /* disabled */
            break;
        }

        case IF_HIGH_SPEED: {
            SET_GAUGE_BIND(binding, LOWER_HALF(iface->mac_stats.speed / 1000000));
            break;
        }

        case IF_PROMISCUOUS_MODE: {
            SET_INTEGER_BIND(binding, iface->mac_stats.promiscuous_state);
            break;
        }

        case IF_CONNECTOR_PRESENT: {
            SET_INTEGER_BIND(binding, has_physical_iface(iface));
            break;
        }

        case IF_ALIAS: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case IF_COUNTER_DISCONTINUITY_TIME: {
            SET_TIME_TICKS_BIND(binding, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_IFX, IF_X_TABLE, column, iface->id)
}

static SnmpErrorStatus get_stack_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    int found = -1;
    int high;
    int low;

    IfaceEntry *head = get_iface_list();
    if (next_row) {
        if (row_len > 1) {
            high = row[0];
            low = row[1];
        } else if (row_len > 0) {
            high = row[0];
            low = -1;
        } else {
            high = -1;
            low = -1;
        }

        if (high < 1) {
            for (IfaceEntry *entry = head;
                    found && entry != NULL; entry = entry->next) {
                if ((int) entry->id > low) {
                    found = 0;
                    high = 0;
                    low = entry->id;
                }
            }

            if (found && head) {
                high = head->id;
                low = 0;
                found = 0;
            }
        } else {
            for (IfaceEntry *entry = head;
                    found && entry != NULL; entry = entry->next) {
                if (entry->id == high && (int) entry->iface_link > low) {
                    found = 0;
                    high = entry->id;
                    low = entry->iface_link;
                } else if ((int) entry->id > high) {
                    found = 0;
                    high = entry->id;
                    low = 0;
                }
            }
        }
    } else if (row_len == 2) {
        for (IfaceEntry *entry = head; found && entry != NULL; entry = entry->next) {
            if ((row[0] == 0 && entry->id == row[1])
                || (row[1] == 0 && entry->id == row[0])
                || (entry->id == row[0] && entry->iface_link == row[1])) {
                found = 0;
                high = row[0];
                low = row[1];
            }
        }
    }

    CHECK_INT_FOUND(next_row, found);

    switch (column) {
        case IF_STACK_HIGHER_LAYER: {
            SET_INTEGER_BIND(binding, high);
            break;
        }

        case IF_STACK_LOWER_LAYER: {
            SET_INTEGER_BIND(binding, low);
            break;
        }

        case IF_STACK_STATUS: {
            SET_INTEGER_BIND(binding, 1); /* active */
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW2(next_row, SNMP_OID_IFX,
            IF_STACK_TABLE, column, high, low)
}

static SnmpErrorStatus get_test_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    IfaceEntry *iface = get_iface_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, iface);

    switch (column) {
        case IF_TEST_ID: {
            SET_INTEGER_BIND(binding, iface->id);
            break;
        }

        case IF_TEST_STATUS: {
            SET_INTEGER_BIND(binding, 1); /* notInUse */
            break;
        }

        case IF_TEST_TYPE:
        case IF_TEST_CODE: {
            SET_OID_BIND(binding, 0, 0);
            break;
        }

        case IF_TEST_RESULT: {
            SET_INTEGER_BIND(binding, 4); /* notSupported */
            break;
        }

        case IF_TEST_OWNER: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_IFX,
            IF_TEST_TABLE, column, iface->id)
}

static SnmpErrorStatus get_rcv_address_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    IfaceEntry *iface = get_iface_addr_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, iface);

    switch (column) {
        case IF_RCV_ADDRESS_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding,
                memdup(iface->address, iface->address_len), iface->address_len);
            break;
        }

        case IF_RCV_ADDRESS_STATUS:
        case IF_RCV_ADDRESS_TYPE: {
            SET_INTEGER_BIND(binding, 1); /* active/other */
            break;
        }
    }

    INSTANCE_FOUND_INT_OCTET_STRING_ROW(next_row, SNMP_OID_IFX,
            IF_RCV_ADDRESS_TABLE, column, iface->id,
            iface->address, iface->address_len)
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    SET_TIME_TICKS_BIND(binding, 0);
    return NO_ERROR;
}

DEF_METHOD(set_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    switch (id) {
        case IF_X_TABLE: {
            return get_ifx_table(column, row, row_len, binding, next_row);
        }

        case IF_STACK_TABLE: {
            return get_stack_table(column, row, row_len, binding, next_row);
        }

        case IF_TEST_TABLE: {
            return get_test_table(column, row, row_len, binding, next_row);
        }

        case IF_RCV_ADDRESS_TABLE: {
            return get_rcv_address_table(column, row, row_len, binding, next_row);
        }

        default: {
            return GENERAL_ERROR;
        }
    }
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *index, size_t index_len,
    SnmpVariableBinding *binding, int dry_run)
{
    return NO_CREATION;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_ifacex_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, IF_X_TABLE,
            IF_STACK_LAST_CHANGE - IF_X_TABLE + 1,
            IF_COUNTER_DISCONTINUITY_TIME, IF_STACK_STATUS, IF_TEST_OWNER,
            IF_RCV_ADDRESS_TYPE, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_IFX);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
