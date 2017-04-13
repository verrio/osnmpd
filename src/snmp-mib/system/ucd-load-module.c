/*
 * This file is part of the osnmpd project (https://github.com/verrio/osnmpd).
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

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <math.h>
#include <sys/sysinfo.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/single-table-module.h"
#include "snmp-mib/system/ucd-module.h"

static const uint32_t sys_load_avg[] = { 1, 5, 15 };

enum UCDLoadTableColumns {
    LA_INDEX = 1,
    LA_NAMES = 2,
    LA_LOAD = 3,
    LA_CONFIG = 4,
    LA_LOAD_INT = 5,
    LA_LOAD_FLOAT = 6
};

static float get_system_load(int avg)
{
    struct sysinfo s_info;
    if (sysinfo(&s_info))
        return NAN;
    return (float) s_info.loads[avg] / (1 << SI_LOAD_SHIFT);
}

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    uint32_t min[] = { 1 };
    uint32_t max[] = { 3 };
    uint32_t index[] = { 0 };
    CHECK_INT_FOUND(next_row,
            search_int_indices(1, min, max, index, row, row_len, next_row));

    switch (column) {
        case LA_INDEX: {
            SET_INTEGER_BIND(binding, index[0]);
            break;
        }

        case LA_NAMES: {
            char buf[64];
            sprintf(buf, "System load average (last %"PRIu32" minutes)",
                    sys_load_avg[index[0]-1]);
            SET_OCTET_STRING_RESULT(binding, strdup(buf), strlen(buf));
            break;
        }

        case LA_LOAD: {
            float load = get_system_load(index[0]-1);
            if (load == NAN)
                return GENERAL_ERROR;
            char buf[32];
            sprintf(buf, "%0.4f", load);
            SET_OCTET_STRING_RESULT(binding, strdup(buf), strlen(buf));
            break;
        }

        case LA_CONFIG: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case LA_LOAD_INT: {
            float load = get_system_load(index[0]-1);
            if (load == NAN)
                return GENERAL_ERROR;
            SET_INTEGER_BIND(binding, 100 * load);
            break;
        }

        case LA_LOAD_FLOAT: {
            float load = get_system_load(index[0]-1);
            if (load == NAN)
                return GENERAL_ERROR;
            SET_OPAQUE_RESULT(binding, memdup(&load, sizeof(load)), sizeof(load));
            break;
        }

        default: {
            return GENERAL_ERROR;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_UCD,
            SNMP_OID_UCD_LOAD_TABLE, column, index[0])
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

MibModule *init_ucd_load_module(void)
{
    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module, LA_INDEX, LA_LOAD_FLOAT)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_UCD_LOAD,1);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
