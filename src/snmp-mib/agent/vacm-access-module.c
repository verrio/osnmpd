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
#include "snmp-mib/agent/vacm-access-module.h"

#define VACM_MIB_COMPLIANCE_OID     SNMP_OID_VACM,2,1,1
#define VACM_ACCESS_TABLE       4
#define VACM_ACCESS_ENTRY       1

static SysOREntry vacm_or_entry = {
    .or_id = {
        .subid = { VACM_MIB_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(VACM_MIB_COMPLIANCE_OID)
    },
    .or_descr = "SNMP-VIEW-BASED-ACM-MIB - View-based Access Control Model for SNMP",
    .next = NULL
};

/* entry indexes (vacmGroupName + vacmAccessContextPrefix +
 * vacmAccessSecurityModel + vacmAccessSecurityLevel) */
static const SubOID access_group_ro[] =
    { 13, 114, 101, 97, 100, 79, 110, 108, 121, 71, 114, 111,
        117, 112, 0, 3, 3 };
static const SubOID access_group_rw[] =
    { 14, 100, 105, 115, 99, 111, 118, 101, 114, 121, 71, 114,
        111, 117, 112, 0, 3, 1 };
static const SubOID access_group_man[] =
    { 15, 109, 97, 110, 97, 103, 101, 109, 101, 110, 116, 71, 114,
        111, 117, 112, 0, 3, 3 };
static const SubOID *access_groups[] = {
    access_group_ro,
    access_group_rw,
    access_group_man
};
static const size_t access_groups_len[] = {
    OID_LENGTH(access_group_ro),
    OID_LENGTH(access_group_rw),
    OID_LENGTH(access_group_man)
};

/* read access view names */
static const char *read_view_names[] = { "all", "discovery", "all" };

/* write access view names */
static const char *write_view_names[] = { "", "", "all" };

enum VacmAccessTableColumns {
    VACM_ACCESS_CONTEXT_MATCH = 4,
    VACM_ACCESS_READ_VIEW_NAME = 5,
    VACM_ACCESS_WRITE_VIEW_NAME = 6,
    VACM_ACCESS_NOTIFY_VIEW_NAME = 7,
    VACM_ACCESS_STORAGE_TYPE = 8,
    VACM_ACCESS_STATUS = 9
};

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    /* get instance */
    int instance = bsearch_oid_indices(access_groups, access_groups_len,
            sizeof(access_groups_len) / sizeof(size_t), row, row_len, next_row);
    const SubOID *access_group = instance < 0 ? NULL : access_groups[instance];
    size_t access_group_len = instance < 0 ? 0 : access_groups_len[instance];
    CHECK_INSTANCE_FOUND(next_row, access_group);

    switch (column) {
        case VACM_ACCESS_CONTEXT_MATCH: {
            /* prefix match */
            SET_INTEGER_BIND(binding, 2);
            break;
        }

        case VACM_ACCESS_READ_VIEW_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(read_view_names[instance]),
                strlen(read_view_names[instance]));
            break;
        }

        case VACM_ACCESS_WRITE_VIEW_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(write_view_names[instance]),
                strlen(write_view_names[instance]));
            break;
        }

        case VACM_ACCESS_NOTIFY_VIEW_NAME: {
            int notify = 0;
            if (instance == 0 && get_trap_configuration()->user == USER_READ_ONLY) {
                notify = 1;
            } else if (instance == 1 && get_trap_configuration()->user == USER_PUBLIC) {
                notify = 1;
            } else if (instance == 2 && (get_trap_configuration()->user == USER_READ_WRITE
                    || get_trap_configuration()->user == USER_ADMIN)) {
                notify = 1;
            }
            if (notify) {
                SET_OCTET_STRING_RESULT(binding, strdup(read_view_names[0]),
                    strlen(read_view_names[0]));
            } else {
                SET_OCTET_STRING_BIND(binding, NULL, 0);
            }
            break;
        }

        case VACM_ACCESS_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case VACM_ACCESS_STATUS: {
            /* active */
            SET_INTEGER_BIND(binding, 1);
            break;
        }
    }

    INSTANCE_FOUND_OID_ROW(next_row, SINGLE_PARAM(SNMP_OID_VACM,1),
            VACM_ACCESS_TABLE, column, access_group, access_group_len);
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

MibModule *init_vacm_access_module(void)
{
    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module,
            VACM_ACCESS_CONTEXT_MATCH, VACM_ACCESS_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_VACM, 1, VACM_ACCESS_TABLE, VACM_ACCESS_ENTRY);
    SET_OR_ENTRY(module, &vacm_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
