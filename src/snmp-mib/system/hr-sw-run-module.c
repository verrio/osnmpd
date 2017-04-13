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

#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <ctype.h>
#include <string.h>

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/system/hr-sw-run-module.h"
#include "snmp-mib/system/proc-cache.h"

enum HRSWRunMIBObjects {
    HR_SW_OS_INDEX = 1,
    HR_SW_RUN_TABLE = 2
};

enum HRSWRunTableColumns {
    HR_SW_RUN_INDEX = 1,
    HR_SW_RUN_NAME = 2,
    HR_SW_RUN_ID = 3,
    HR_SW_RUN_PATH = 4,
    HR_SW_RUN_PARAMETERS = 5,
    HR_SW_RUN_TYPE = 6,
    HR_SW_RUN_STATUS = 7
};

static void read_stats_file(uint32_t pid, char *buf, size_t buf_len)
{
    char stat_file[64];
    snprintf(stat_file, sizeof(stat_file), LINUX_PROC_STAT, pid);

    FILE *f = fopen(stat_file, "r");
    if (f == NULL || fgets(buf, buf_len, f) == NULL) {
        buf[0] = '\0';
    }
    if (f != NULL) {
        fclose(f);
    }
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    SET_INTEGER_BIND(binding, 1);
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
    uint32_t pid = -1;
    if (next_row) {
        pid = get_next_pid(row_len < 1 ? 0 : row[0]);
    } else if (row_len == 1 && !pid_exists(row[0])) {
        pid = row[0];
    }

    CHECK_INT_FOUND(next_row, pid);

    switch (column) {
        case HR_SW_RUN_INDEX: {
            SET_INTEGER_BIND(binding, pid);
            break;
        }

        case HR_SW_RUN_NAME: {
            char stat_buf[512];
            read_stats_file(pid, stat_buf, sizeof(stat_buf));

            char *ptr;
            char *tok = strtok_r(stat_buf, " ", &ptr);
            tok = strtok_r(NULL, " ", &ptr);
            if (tok == NULL) {
                /* process gone */
                SET_OCTET_STRING_BIND(binding, NULL, 0);
            } else {
                int len = strlen(tok);
                if (len < 2) {
                    return GENERAL_ERROR;
                }
                SET_OCTET_STRING_RESULT(binding, strdup(tok + 1), len - 2);
            }
            break;
        }

        case HR_SW_RUN_ID: {
            SET_OID_BIND(binding, 0, 0);
            break;
        }

        case HR_SW_RUN_PATH: {
            char exe_file[64];
            snprintf(exe_file, sizeof(exe_file), LINUX_PROC_EXE, pid);
            char *bin_path = malloc(512 * sizeof(char));
            if (bin_path == NULL)
                return GENERAL_ERROR;

            bin_path[0] = '\0';
            int size = readlink(exe_file, bin_path, 512 * sizeof(char));
            SET_OCTET_STRING_BIND(binding, (uint8_t *) bin_path, size < 0 ? 0 : size);
            break;
        }

        case HR_SW_RUN_PARAMETERS: {
            char cmdline_file[64];
            snprintf(cmdline_file, sizeof(cmdline_file), LINUX_PROC_CMDLINE, pid);

            int empty = 0;
            char line_buf[1024];
            memset(line_buf, 0, sizeof(line_buf));

            FILE *f = fopen(cmdline_file, "r");
            if (f == NULL || fgets(line_buf, sizeof(line_buf), f) == NULL)
                empty = 1;
            if (f != NULL)
                fclose(f);
            if (empty)
                goto no_args;

            char *args = line_buf;
            while (*args) args++;
            args++;
            if (args >= line_buf + sizeof(line_buf) || !*args)
                goto no_args;

            line_buf[1023] = '\0';
            for (char *offset = args;
                offset < line_buf + sizeof(line_buf) - 1; offset++) {
                if (*offset == '\0' && *(offset + 1))
                    *offset = ' ';
            }
            SET_OCTET_STRING_RESULT(binding, strdup(args), strlen(args));
            break;

        no_args:
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case HR_SW_RUN_TYPE: {
            char cmdline_file[64];
            snprintf(cmdline_file, sizeof(cmdline_file), LINUX_PROC_CMDLINE, pid);

            char cmd[64];
            cmd[0] = '\0';
            FILE *f = fopen(cmdline_file, "r");
            if (f == NULL)
                SET_INTEGER_BIND(binding, 1); /* unknown */
            else if (fgets(cmd, sizeof(cmd), f) == NULL)
                SET_INTEGER_BIND(binding, 2); /* system */
            else
                SET_INTEGER_BIND(binding, 4); /* application */
            if (f != NULL)
                fclose(f);
            break;
        }

        case HR_SW_RUN_STATUS: {
            char stat_buf[512];
            read_stats_file(pid, stat_buf, sizeof(stat_buf));

            char *ptr;
            char *tok = strtok_r(stat_buf, " ", &ptr);
            for (int i = 0; i < 2 && tok != NULL; i++)
                tok = strtok_r(NULL, " ", &ptr);
            int state;
            if (tok == NULL) {
                /* process gone */
                state = 4; /* invalid */
            } else {
                switch (*tok) {
                    case 'R': {
                        state = 1; /* running */
                        break;
                    }

                    case 'S': {
                        state = 2; /* runnable */
                        break;
                    }

                    case 'D':
                    case 'T': {
                        state = 3; /* notRunnable */
                        break;
                    }

                    default: {
                        state = 4; /* invalid */
                    }
                }
            }

            SET_INTEGER_BIND(binding, state);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_HR_SW_RUN, id, column, pid);
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *index, size_t index_len,
    SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_hr_sw_run_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, HR_SW_OS_INDEX,
        HR_SW_RUN_TABLE - HR_SW_OS_INDEX + 1, LEAF_SCALAR, HR_SW_RUN_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_HR_SW_RUN);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
