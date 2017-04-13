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

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/single-table-module.h"
#include "snmp-mib/system/proc-cache.h"
#include "snmp-mib/system/hr-sw-perf-module.h"

enum HRSWRunPerfTableColumns {
    HR_SW_RUN_PERF_CPU = 1,
    HR_SW_RUN_PERF_MEM = 2
};

static void read_stats_file(int statm, uint32_t pid, char *buf, size_t buf_len)
{
    char stat_file[64];
    snprintf(stat_file, sizeof(stat_file),
        statm ? LINUX_PROC_STATM : LINUX_PROC_STAT, pid);

    FILE *f = fopen(stat_file, "r");
    if (f == NULL || fgets(buf, buf_len, f) == NULL) {
        buf[0] = '\0';
    }
    if (f != NULL) {
        fclose(f);
    }
}

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    uint32_t pid = -1;
    if (next_row) {
        pid = get_next_pid(row_len < 1 ? 0 : row[0]);
    } else if (row_len == 1 && !pid_exists(row[0])) {
        pid = row[0];
    }

    CHECK_INT_FOUND(next_row, pid);

    switch (column) {
        case HR_SW_RUN_PERF_CPU: {
            char stat_buf[512];
            read_stats_file(0, pid, stat_buf, sizeof(stat_buf));

            char *ptr;
            char *tok = strtok_r(stat_buf, " ", &ptr);
            for (int i = 0; i < 13 && tok != NULL; i++)
                tok = strtok_r(NULL, " ", &ptr);
            if (tok == NULL) {
                /* process gone */
                SET_INTEGER_BIND(binding, 0);
            } else {
                /* utime + stime */
                uint32_t jiffies = atol(tok);
                tok = strtok_r(NULL, " ", &ptr);
                if (tok == NULL)
                    return GENERAL_ERROR;
                jiffies += atol(tok);
                SET_INTEGER_BIND(binding, 100 * jiffies / sysconf(_SC_CLK_TCK));
            }
            break;
        }

        case HR_SW_RUN_PERF_MEM: {
            char stat_buf[512];
            read_stats_file(1, pid, stat_buf, sizeof(stat_buf));

            char *ptr;
            char *tok = strtok_r(stat_buf, " ", &ptr);
            tok = strtok_r(NULL, " ", &ptr);
            if (tok == NULL) {
                /* process gone */
                SET_INTEGER_BIND(binding, 0);
            } else {
                /* resident memory */
                SET_INTEGER_BIND(binding, (atol(tok) * getpagesize()) >> 10);
            }
            break;
        }

        default: {
            return GENERAL_ERROR;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_HR_SW_PERF, 1, column, pid)
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

MibModule *init_hr_sw_perf_module(void)
{
    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module,
        HR_SW_RUN_PERF_CPU, HR_SW_RUN_PERF_MEM)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_HR_SW_PERF,1,1);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
