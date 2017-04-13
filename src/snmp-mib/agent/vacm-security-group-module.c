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

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-agent/agent-config.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/single-table-module.h"
#include "snmp-mib/agent/vacm-security-group-module.h"

#define VACM_SECURITY_TO_GROUP_TABLE       2
#define VACM_SECURITY_TO_GROUP_ENTRY       1

static const char *group_names[] = {
    "discoveryGroup",
    "readOnlyGroup",
    "readWriteGroup",
    "managementGroup"
};

enum VacmSecurityToGroupTableColumns {
    VACM_GROUP_NAME = 3,
    VACM_SECURITY_TO_GROUP_STORAGE_TYPE = 4,
    VACM_SECURITY_TO_GROUP_STATUS = 5
};

static SnmpUserSlot get_user_slot(SubOID *row, size_t row_len, int next_row)
{
    int first_row = 0;

    /* first part of index : vacmSecurityModel */
    if (row_len < 1 || row[0] < 3) {
        if (next_row) {
            /* first entry */
            first_row = 1;
        } else {
            return -1;
        }
    } else if (row[0] > 3) {
        return -1;
    }

    /* second part of index: vacmSecurityName */
    const char *security_names[NUMBER_OF_USER_SLOTS];
    security_names[0] = get_user_configuration(USER_PUBLIC)->name;
    security_names[1] = get_user_configuration(USER_READ_ONLY)->name;
    security_names[2] = get_user_configuration(USER_READ_WRITE)->name;
    security_names[3] = get_user_configuration(USER_ADMIN)->name;
    return (SnmpUserSlot) lsearch_string_indices(security_names,
        NUMBER_OF_USER_SLOTS, row + 1, first_row ? 0 : row_len - 1, next_row);
}

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    /* get instance */
    SnmpUserSlot user_slot = get_user_slot(row, row_len, next_row);
    const char *group_name  = user_slot == -1 ? NULL : group_names[user_slot];
    CHECK_INSTANCE_FOUND(next_row, group_name);

    switch (column) {
        case VACM_GROUP_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(group_name), strlen(group_name));
            break;
        }

        case VACM_SECURITY_TO_GROUP_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case VACM_SECURITY_TO_GROUP_STATUS: {
            /* active/notInService */
            SET_INTEGER_BIND(binding, 1);
            break;
        }
    }

    if (next_row) {
        SET_OID(binding->oid, SNMP_OID_VACM, 1,
            VACM_SECURITY_TO_GROUP_TABLE, 1, column, 3);
        if (fill_row_index_string(&((binding)->oid),
                (uint8_t *) get_user_configuration(user_slot)->name,
                strlen(get_user_configuration(user_slot)->name))) {
            return GENERAL_ERROR;
        }
    }

    return NO_ERROR;
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

MibModule *init_vacm_security_group_module(void)
{
    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module,
            VACM_GROUP_NAME, VACM_SECURITY_TO_GROUP_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_VACM, 1,
        VACM_SECURITY_TO_GROUP_TABLE, VACM_SECURITY_TO_GROUP_ENTRY);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
