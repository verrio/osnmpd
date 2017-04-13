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
#include "snmp-mib/system/hr-storage-module.h"
#include "snmp-mib/system/storage-cache.h"

enum HRStorageMIBObjects {
    HR_MEMORY_SIZE = 2,
    HR_STORAGE_TABLE = 3
};

enum HRStorageTableColumns {
    HR_STORAGE_INDEX = 1,
    HR_STORAGE_TYPE = 2,
    HR_STORAGE_DESCR = 3,
    HR_STORAGE_ALLOCATION_UNITS = 4,
    HR_STORAGE_SIZE = 5,
    HR_STORAGE_USED = 6,
    HR_STORAGE_ALLOCATION_FAILURES = 7
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    struct sysinfo info;
    if (sysinfo(&info) == -1) {
        return GENERAL_ERROR;
    }
    SET_INTEGER_BIND(binding, info.totalram >> 10);
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
    StorageEntry *entry;
    for (entry = get_storage_list(); entry != NULL; entry = entry->next) {
        if (next_row) {
            if (row_len < 1 || row[0] < entry->index) {
                break;
            }
        } else if (row_len == 1 && row[0] == entry->index) {
            break;
        }
    }

    CHECK_INSTANCE_FOUND(next_row, entry);

    switch (column) {
        case HR_STORAGE_INDEX: {
            SET_INTEGER_BIND(binding, entry->index);
            break;
        }

        case HR_STORAGE_TYPE: {
            SET_OID_BIND(binding, 0, 0);
            break;
        }

        case HR_STORAGE_DESCR: {
            SET_OCTET_STRING_RESULT(binding,
                (uint8_t *) strdup(entry->descr), strlen(entry->descr));
            break;
        }

        case HR_STORAGE_ALLOCATION_UNITS: {
            SET_INTEGER_BIND(binding, entry->allocation_units);
            break;
        }

        case HR_STORAGE_SIZE: {
            SET_INTEGER_BIND(binding, entry->size);
            break;
        }

        case HR_STORAGE_USED: {
            SET_INTEGER_BIND(binding, entry->used);
            break;
        }

        case HR_STORAGE_ALLOCATION_FAILURES: {
            SET_UNSIGNED_BIND(binding, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_HR_STORAGE,
            HR_STORAGE_TABLE, column, entry->index);
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

MibModule *init_hr_storage_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, HR_MEMORY_SIZE,
            HR_STORAGE_TABLE - HR_MEMORY_SIZE + 1,
            LEAF_SCALAR, HR_STORAGE_ALLOCATION_FAILURES)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_HR_STORAGE);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
