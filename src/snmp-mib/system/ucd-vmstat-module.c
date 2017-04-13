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
#include <unistd.h>
#include <stdio.h>
#include <sys/sysinfo.h>

#include "snmp-agent/mib-tree.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/system/ucd-module.h"
#include "snmp-mib/system/cpu-cache.h"

static const char *vmstat_error_name = "systemStats";

enum UCDMemoryMIBObjects {
    SS_INDEX = 1,
    SS_ERROR_NAME = 2,
    SS_SWAP_IN = 3,
    SS_SWAP_OUT = 4,
    SS_IO_SENT = 5,
    SS_IO_RECEIVE = 6,
    SS_SYS_INTERRUPTS = 7,
    SS_SYS_CONTEXT = 8,
    SS_CPU_USER = 9,
    SS_CPU_SYSTEM = 10,
    SS_CPU_IDLE = 11
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    CpuInfo *cpu_info = get_cpu_info();
    if (cpu_info == NULL) {
        return GENERAL_ERROR;
    }

    switch (id) {
        case SS_INDEX: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case SS_ERROR_NAME: {
            SET_OCTET_STRING_RESULT(binding,
                strdup(vmstat_error_name), strlen(vmstat_error_name));
            break;
        }

        case SS_SWAP_IN: {
            SET_INTEGER_BIND(binding, cpu_info->swap_in);
            break;
        }

        case SS_SWAP_OUT: {
            SET_INTEGER_BIND(binding, cpu_info->swap_out);
            break;
        }

        case SS_IO_SENT: {
            SET_INTEGER_BIND(binding, cpu_info->io_sent);
            break;
        }

        case SS_IO_RECEIVE: {
            SET_INTEGER_BIND(binding, cpu_info->io_received);
            break;
        }

        case SS_SYS_INTERRUPTS: {
            SET_INTEGER_BIND(binding, cpu_info->interrupts);
            return NO_ERROR;
        }

        case SS_SYS_CONTEXT: {
            SET_INTEGER_BIND(binding, cpu_info->context_switch);
            break;
        }

        case SS_CPU_USER: {
            SET_INTEGER_BIND(binding, cpu_info->cpu_user);
            break;
        }

        case SS_CPU_SYSTEM: {
            SET_INTEGER_BIND(binding, cpu_info->cpu_system);
            break;
        }

        case SS_CPU_IDLE: {
            SET_INTEGER_BIND(binding, cpu_info->cpu_idle);
            break;
        }

        default: {
            return GENERAL_ERROR;
        }
    }

    return NO_ERROR;
}

DEF_METHOD(set_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_ucd_vmstat_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, SS_INDEX, SS_CPU_IDLE - SS_INDEX + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_UCD_CPU);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
