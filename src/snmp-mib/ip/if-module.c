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
#include "snmp-mib/ip/if-module.h"

#define IF_COMPLIANCE_OID   SNMP_OID_MIB2,31,2,2,3

static SysOREntry if_stats_or_entry = {
    .or_id = {
        .subid = { IF_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(IF_COMPLIANCE_OID)
    },
    .or_descr = "IF-MIB - interface statistics",
    .next = NULL
};

enum IFMIBObjects {
    IF_NUMBER = 1,
    IF_TABLE = 2
};

enum IPAddrTableColumns {
    IF_INDEX = 1,
    IF_DESCR = 2,
    IF_TYPE = 3,
    IF_MTU = 4,
    IF_SPEED = 5,
    IF_PHYS_ADDRESS = 6,
    IF_ADMIN_STATUS = 7,
    IF_OPER_STATUS = 8,
    IF_LAST_CHANGE = 9,
    IF_IN_OCTETS = 10,
    IF_IN_UCAST_PKTS = 11,
    IF_IN_N_UCAST_PKTS = 12,
    IF_IN_DISCARDS = 13,
    IF_IN_ERRORS = 14,
    IF_IN_UNKNOWN_PROTOS = 15,
    IF_OUT_OCTETS = 16,
    IF_OUT_UCAST_PKTS = 17,
    IF_OUT_N_UCAST_PKTS = 18,
    IF_OUT_DISCARDS = 19,
    IF_OUT_ERRORS = 20,
    IF_OUT_Q_LEN = 21,
    IF_SPECIFIC = 22
};

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

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    int count = 0;
    for (IfaceEntry *iface = get_iface_list();
            iface != NULL; iface = iface->next, count++);
    SET_INTEGER_BIND(binding, count);
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
    IfaceEntry *iface = get_iface_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, iface);

    switch (column) {
        case IF_INDEX: {
            SET_INTEGER_BIND(binding, iface->id);
            break;
        }

        case IF_DESCR: {
            char *descr = strnlen(iface->iface_descr, MAX_IF_DESCR) > 0 ?
                    iface->iface_descr : iface->iface_name;
            SET_OCTET_STRING_RESULT(binding, strndup(descr, MAX_IF_DESCR),
                    strnlen(descr, MAX_IF_DESCR));
            break;
        }

        case IF_TYPE: {
            SET_INTEGER_BIND(binding, iface->type);
            break;
        }

        case IF_MTU: {
            SET_INTEGER_BIND(binding, iface->mac_stats.mtu);
            break;
        }

        case IF_SPEED: {
            SET_GAUGE_BIND(binding, LOWER_HALF(iface->mac_stats.speed));
            break;
        }

        case IF_PHYS_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding,
                memdup(iface->address, iface->address_len), iface->address_len);
            break;
        }

        case IF_ADMIN_STATUS: {
            SET_INTEGER_BIND(binding, iface->mac_stats.admin_state);
            break;
        }

        case IF_OPER_STATUS: {
            SET_INTEGER_BIND(binding, iface->mac_stats.oper_state);
            break;
        }

        case IF_LAST_CHANGE: {
            SET_TIME_TICKS_BIND(binding, 0);
            break;
        }

        case IF_IN_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.in_octets));
            break;
        }

        case IF_IN_UCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.in_ucast_pkts));
            break;
        }

        case IF_IN_N_UCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.in_bcast_pkts +
                    iface->mac_stats.in_mcast_pkts));
            break;
        }

        case IF_IN_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.in_discards));
            break;
        }

        case IF_IN_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.in_errs));
            break;
        }

        case IF_IN_UNKNOWN_PROTOS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.in_unknown_proto));
            break;
        }

        case IF_OUT_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.out_octets));
            break;
        }

        case IF_OUT_UCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.out_ucast_pkts));
            break;
        }

        case IF_OUT_N_UCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.out_bcast_pkts +
                    iface->mac_stats.out_mcast_pkts));
            break;
        }

        case IF_OUT_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.out_discards));
            break;
        }

        case IF_OUT_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->mac_stats.out_errs));
            break;
        }

        case IF_OUT_Q_LEN: {
            SET_GAUGE_BIND(binding, iface->mac_stats.tx_qlen);
            break;
        }

        case IF_SPECIFIC: {
            SET_OID_BIND(binding, 0, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_IF, IF_TABLE, column, iface->id)
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

MibModule *init_iface_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, IF_NUMBER,
            IF_TABLE - IF_NUMBER + 1, LEAF_SCALAR, IF_SPECIFIC)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_IF);
    SET_OR_ENTRY(module, &if_stats_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
