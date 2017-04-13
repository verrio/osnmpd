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
#include "snmp-mib/single-table-module.h"
#include "snmp-mib/ip/if-cache.h"
#include "snmp-mib/ip/ip-cache.h"
#include "snmp-mib/ip/ip-address-cache.h"
#include "snmp-mib/ip/if-inverted-module.h"

#define IF_INVERTED_COMPLIANCE_OID   SNMP_OID_MIB2,77,1,2,2,1

static SysOREntry if_inverted_stack_or_entry = {
    .or_id = {
        .subid = { IF_INVERTED_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(IF_INVERTED_COMPLIANCE_OID)
    },
    .or_descr = "IF-INVERTED-STACK-MIB - inverted interface stack",
    .next = NULL
};

enum IFInvertedStackTableColumns {
    IF_INV_STACK_STATUS = 1
};

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    int found = -1;
    int low;
    int high;

    IfaceEntry *head = get_iface_list();
    if (next_row) {
        if (row_len > 1) {
            low = row[0];
            high = row[1];
        } else if (row_len > 0) {
            low = row[0];
            high = -1;
        } else {
            low = -1;
            high = -1;
        }

        if (low < 1) {
            for (IfaceEntry *entry = head;
                    found && entry != NULL; entry = entry->next) {
                if ((int) entry->id > high) {
                    found = 0;
                    low = 0;
                    high = entry->id;
                }
            }

            if (found && head) {
                low = head->id;
                high = 0;
                found = 0;
            }
        } else {
            int higher = INT32_MAX;

            for (IfaceEntry *entry = head; entry != NULL; entry = entry->next) {
                if (entry->iface_link == low && (int) entry->id > high && (int) entry->id < higher) {
                    found = 0;
                    higher = entry->id;
                }
            }

            if (found) {
                for (IfaceEntry *entry = head; entry != NULL; entry = entry->next) {
                    if (entry->id > low) {
                        found = 0;
                        low = entry->id;
                        high = 0;
                        break;
                    }
                }
            } else {
                high = higher;
            }
        }
    } else if (row_len == 2) {
        for (IfaceEntry *entry = head; found && entry != NULL; entry = entry->next) {
            if ((row[0] == 0 && entry->id == row[1])
                || (row[1] == 0 && entry->id == row[0])
                || (entry->id == row[1] && entry->iface_link == row[0])) {
                found = 0;
                low = row[0];
                high = row[1];
            }
        }
    }

    CHECK_INT_FOUND(next_row, found);
    SET_INTEGER_BIND(binding, 1); /* active */
    INSTANCE_FOUND_INT_ROW2(next_row, SNMP_OID_IF_INVERTED, 1, 1, low, high)
}

DEF_METHOD(set_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *index, size_t index_len, SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleTableMibModule)
{
    finish_single_table_module(this);
}

MibModule *init_inverted_iface_module(void)
{
    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module,
        IF_INV_STACK_STATUS, IF_INV_STACK_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_IF_INVERTED, 1, 1);
    SET_OR_ENTRY(module, &if_inverted_stack_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
