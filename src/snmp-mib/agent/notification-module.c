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

#include "snmp-agent/agent-config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/target-module.h"
#include "snmp-mib/agent/notification-module.h"

#define NOTIFICATION_MIB_OID        SNMP_OID_SNMPMODULES,13,1
#define NOTIFICATION_MIB_COMPLIANCE_OID   SNMP_OID_SNMPMODULES,13,3,1,1
#define NOTIFICATION_TAG    "upstream"
#define MAIN_FILTER_PROFILE "filtered"

static SysOREntry notification_or_entry = {
    .or_id = {
        .subid = { NOTIFICATION_MIB_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(NOTIFICATION_MIB_COMPLIANCE_OID)
    },
    .or_descr = "SNMP-NOTIFICATION-MIB - parameters for the generation of notifications",
    .next = NULL
};

/* single notification table row */
static const char *table_idx_name = "internal";
static SubOID table_idx[] = { 105, 110, 116, 101, 114, 110, 97, 108 };
static size_t table_idx_len = OID_LENGTH(table_idx);

/* single notification filter table row */
static SubOID filter_table_idx[] = { 8, 117, 112, 115, 116, 114, 101, 97, 109, 1, 3, 6 };
static size_t filter_table_idx_len = OID_LENGTH(filter_table_idx);

/* MIB objects */
enum NotificationMIBObjects {
    SNMP_NOTIFY_TABLE = 1,
    SNMP_NOTIFY_FILTER_PROFILE_TABLE = 2,
    SNMP_NOTIFY_FILTER_TABLE = 3
};

/* table columns of the notify table */
enum NotifyColumns {
    SNMP_NOTIFY_NAME = 1,
    SNMP_NOTIFY_TAG = 2,
    SNMP_NOTIFY_TYPE = 3,
    SNMP_NOTIFY_STORAGE_TYPE = 4,
    SNMP_NOTIFY_ROW_STATUS = 5
};

/* table columns of the notify filter profile table */
enum NotifyFilterProfileColumns {
    SNMP_NOTIFY_FILTER_PROFILE_NAME = 1,
    SNMP_NOTIFY_FILTER_PROFILE_STOR_TYPE = 2,
    SNMP_NOTIFY_FILTER_PROFILE_ROW_STATUS = 3
};

/* table columns of the notify filter table */
enum NotifyFilterColumns {
    SNMP_NOTIFY_FILTER_SUBTREE = 1,
    SNMP_NOTIFY_FILTER_MASK = 2,
    SNMP_NOTIFY_FILTER_TYPE = 3,
    SNMP_NOTIFY_FILTER_STORAGE_TYPE = 4,
    SNMP_NOTIFY_FILTER_ROW_STATUS = 5
};

static SnmpErrorStatus get_notify_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    /* single instance */
    int cmp = cmp_index_to_oid(table_idx, table_idx_len, row, row_len);
    if (next_row && cmp >= 0) {
        binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
        return NO_ERROR;
    } else if (!next_row && cmp) {
        binding->type = SMI_EXCEPT_NO_SUCH_INSTANCE;
        return NO_ERROR;
    }

    switch (column) {
        case SNMP_NOTIFY_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(table_idx_name),
                    strlen(table_idx_name));
            break;
        }

        case SNMP_NOTIFY_TAG: {
            SET_OCTET_STRING_RESULT(binding, strdup(NOTIFICATION_TAG),
                    strlen(NOTIFICATION_TAG));
            break;
        }

        case SNMP_NOTIFY_TYPE: {
            SET_INTEGER_BIND(binding, get_trap_configuration()->confirmed ? 2 : 1);
            break;
        }

        case SNMP_NOTIFY_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case SNMP_NOTIFY_ROW_STATUS: {
            /* active/notInService */
            SET_INTEGER_BIND(binding, get_trap_configuration()->enabled ? 1 : 2);
            break;
        }
    }

    INSTANCE_FOUND_OID_ROW(next_row, NOTIFICATION_MIB_OID, SNMP_NOTIFY_TABLE,
            column, table_idx, table_idx_len);
}

static SnmpErrorStatus get_notify_filter_profile_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    /* single instance */
    int cmp = cmp_index_to_oid(target_table_idx, target_table_idx_len, row, row_len);
    if (next_row && cmp >= 0) {
        binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
        return NO_ERROR;
    } else if (!next_row && cmp) {
        binding->type = SMI_EXCEPT_NO_SUCH_INSTANCE;
        return NO_ERROR;
    }

    switch (column) {
        case SNMP_NOTIFY_FILTER_PROFILE_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(MAIN_FILTER_PROFILE),
                    strlen(MAIN_FILTER_PROFILE));
            break;
        }

        case SNMP_NOTIFY_FILTER_PROFILE_STOR_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case SNMP_NOTIFY_FILTER_PROFILE_ROW_STATUS: {
            /* active/notInService */
            SET_INTEGER_BIND(binding, get_trap_configuration()->enabled ? 1 : 2);
            break;
        }
    }

    INSTANCE_FOUND_OID_ROW(next_row, NOTIFICATION_MIB_OID, SNMP_NOTIFY_FILTER_PROFILE_TABLE,
            column, target_table_idx, target_table_idx_len);
}

static SnmpErrorStatus get_notify_filter_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    /* single instance */
    int cmp = cmp_index_to_oid(filter_table_idx, filter_table_idx_len, row, row_len);
    if (next_row && cmp >= 0) {
        binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
        return NO_ERROR;
    } else if (!next_row && cmp) {
        binding->type = SMI_EXCEPT_NO_SUCH_INSTANCE;
        return NO_ERROR;
    }

    switch (column) {
        case SNMP_NOTIFY_FILTER_SUBTREE: {
            SET_OID_BIND(binding, 1, 3, 6);
            break;
        }

        case SNMP_NOTIFY_FILTER_MASK: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case SNMP_NOTIFY_FILTER_TYPE: {
            /* included */
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case SNMP_NOTIFY_FILTER_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case SNMP_NOTIFY_FILTER_ROW_STATUS: {
            /* active */
            SET_INTEGER_BIND(binding, 1);
            break;
        }
    }

    INSTANCE_FOUND_OID_ROW(next_row, NOTIFICATION_MIB_OID, SNMP_NOTIFY_FILTER_TABLE,
            column, filter_table_idx, filter_table_idx_len);
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    switch (id) {
        case SNMP_NOTIFY_TABLE: {
            return get_notify_table(column, row, row_len, binding, next_row);
        }

        case SNMP_NOTIFY_FILTER_PROFILE_TABLE: {
            return get_notify_filter_profile_table(column, row, row_len, binding, next_row);
        }

        case SNMP_NOTIFY_FILTER_TABLE: {
            return get_notify_filter_table(column, row, row_len, binding, next_row);
        }

        default: {
            return GENERAL_ERROR;
        }
    }
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

MibModule *init_notification_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, SNMP_NOTIFY_TABLE,
        SNMP_NOTIFY_FILTER_TABLE - SNMP_NOTIFY_NAME + 1,
        SNMP_NOTIFY_ROW_STATUS, SNMP_NOTIFY_FILTER_PROFILE_ROW_STATUS,
        SNMP_NOTIFY_FILTER_ROW_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, NOTIFICATION_MIB_OID);
    SET_OR_ENTRY(module, &notification_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
