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

#include "snmp-agent/agent-notification-log.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/notification-module.h"

#define NOTIFICATION_LOG_CONFIG_OID     NOTIFICATION_LOG_MIB_OID,1,1

enum NotificationLogConfigMIBObjects {
    NLM_CONFIG_GLOBAL_ENTRY_LIMIT = 1,
    NLM_CONFIG_GLOBAL_AGE_OUT = 2,
    NLM_CONFIG_LOG_TABLE = 3
};

enum NotificationLogConfigTableColumns {
    NLM_LOG_NAME = 1,
    NLM_CONFIG_LOG_FILTER_NAME = 2,
    NLM_CONFIG_LOG_ENTRY_LIMIT = 3,
    NLM_CONFIG_LOG_ADMIN_STATUS = 4,
    NLM_CONFIG_LOG_OPER_STATUS = 5,
    NLM_CONFIG_LOG_STORAGE_TYPE = 6,
    NLM_CONFIG_LOG_ENTRY_STATUS = 7
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case NLM_CONFIG_GLOBAL_ENTRY_LIMIT: {
            SET_GAUGE_BIND(binding, get_max_log_entries());
            break;
        }

        case NLM_CONFIG_GLOBAL_AGE_OUT: {
            SET_GAUGE_BIND(binding, 0);
            break;
        }
    }

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
    /* single instance */
    int cmp = cmp_index_to_array((const uint8_t * const) notification_log_name,
            strlen(notification_log_name), row, row_len);
    if (next_row && cmp >= 0) {
        binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
        return NO_ERROR;
    } else if (!next_row && cmp) {
        binding->type = SMI_EXCEPT_NO_SUCH_INSTANCE;
        return NO_ERROR;
    }

    switch (column) {
        case NLM_LOG_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(notification_log_name),
                strlen(notification_log_name));
            break;
        }

        case NLM_CONFIG_LOG_FILTER_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(notification_filter_name),
                strlen(notification_filter_name));
            break;
        }

        case NLM_CONFIG_LOG_ENTRY_LIMIT: {
            SET_GAUGE_BIND(binding, get_max_log_entries());
            break;
        }

        case NLM_CONFIG_LOG_ADMIN_STATUS: {
            /* enabled */
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case NLM_CONFIG_LOG_OPER_STATUS: {
            /* operational */
            SET_INTEGER_BIND(binding, 2);
            break;
        }

        case NLM_CONFIG_LOG_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case NLM_CONFIG_LOG_ENTRY_STATUS: {
            /* active */
            SET_INTEGER_BIND(binding, 1);
            break;
        }
    }

    INSTANCE_FOUND_OCTET_STRING_ROW(next_row, NOTIFICATION_LOG_CONFIG_OID,
        NLM_CONFIG_LOG_TABLE, column, (uint8_t *) notification_log_name,
        strlen(notification_log_name));
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

MibModule *init_notification_log_config_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, NLM_CONFIG_GLOBAL_ENTRY_LIMIT,
        NLM_CONFIG_LOG_TABLE - NLM_CONFIG_GLOBAL_ENTRY_LIMIT + 1,
        LEAF_SCALAR, LEAF_SCALAR, NLM_CONFIG_LOG_ENTRY_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, NOTIFICATION_LOG_CONFIG_OID);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
