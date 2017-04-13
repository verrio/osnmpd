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
#include "snmp-mib/system/mem-cache.h"

#define SNMP_OID_UCD_COMPLIANCE_OID   SNMP_OID_UCD

static SysOREntry ucd_or_entry = {
    .or_id = {
        .subid = { SNMP_OID_UCD_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(SNMP_OID_UCD_COMPLIANCE_OID)
    },
    .or_descr = "UCD-SNMP-MIB - Net-SNMP defined extensions",
    .next = NULL
};

static const char *mem_error_name = "swap";

enum UCDMemoryMIBObjects {
    MEM_INDEX = 1,
    MEM_ERROR_NAME = 2,
    MEM_TOTAL_SWAP = 3,
    MEM_AVAIL_SWAP = 4,
    MEM_TOTAL_REAL = 5,
    MEM_AVAIL_REAL = 6,
    MEM_TOTAL_FREE = 11,
    MEM_MINIMUM_SWAP = 12,
    MEM_SHARED = 13,
    MEM_BUFFER = 14,
    MEM_CACHED = 15
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    MemoryInfo *mem_info = get_memory_info();
    if (mem_info == NULL) {
        return GENERAL_ERROR;
    }

    switch (id) {
        case MEM_INDEX: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case MEM_ERROR_NAME: {
            SET_OCTET_STRING_RESULT(binding,
                strdup(mem_error_name), strlen(mem_error_name));
            break;
        }

        case MEM_TOTAL_SWAP: {
            SET_INTEGER_BIND(binding, mem_info->swap_total);
            break;
        }

        case MEM_AVAIL_SWAP: {
            SET_INTEGER_BIND(binding, mem_info->swap_free);
            break;
        }

        case MEM_TOTAL_REAL: {
            SET_INTEGER_BIND(binding, mem_info->mem_total);
            break;
        }

        case MEM_AVAIL_REAL: {
            SET_INTEGER_BIND(binding, mem_info->mem_free);
            break;
        }

        case MEM_TOTAL_FREE: {
            SET_INTEGER_BIND(binding, mem_info->mem_free + mem_info->swap_free);
            return NO_ERROR;
        }

        case MEM_MINIMUM_SWAP: {
            SET_INTEGER_BIND(binding, mem_info->swap_min);
            break;
        }

        case MEM_SHARED: {
            SET_INTEGER_BIND(binding, mem_info->mem_shared);
            break;
        }

        case MEM_BUFFER: {
            SET_INTEGER_BIND(binding, mem_info->mem_buffers);
            break;
        }

        case MEM_CACHED: {
            SET_INTEGER_BIND(binding, mem_info->mem_cached);
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

MibModule *init_ucd_memory_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, MEM_INDEX, MEM_CACHED - MEM_INDEX + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_UNUSED, LEAF_UNUSED, LEAF_UNUSED, LEAF_UNUSED,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_UCD_MEM);
    SET_OR_ENTRY(module, &ucd_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
