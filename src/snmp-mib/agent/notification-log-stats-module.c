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

#define NOTIFICATION_LOG_STATS_OID     NOTIFICATION_LOG_MIB_OID,1,2

enum NotificationLogStatsMIBObjects {
    NLM_STATS_GLOBAL_NOTIFICATIONS_LOGGED = 1,
    NLM_STATS_GLOBAL_NOTIFICATIONS_BUMPED = 2,
    NLM_STATS_LOG_TABLE = 3
};

enum NotificationLogStatsTableColumns {
    NLM_STATS_LOG_NOTIFICATIONS_LOGGED = 1,
    NLM_STATS_LOG_NOTIFICATIONS_BUMPED = 2
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case NLM_STATS_GLOBAL_NOTIFICATIONS_LOGGED: {
            SET_UNSIGNED_BIND(binding, get_num_log_entries());
            break;
        }

        case NLM_STATS_GLOBAL_NOTIFICATIONS_BUMPED: {
            SET_UNSIGNED_BIND(binding, get_num_log_discarded());
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
        case NLM_STATS_LOG_NOTIFICATIONS_LOGGED: {
            SET_UNSIGNED_BIND(binding, get_num_log_entries());
            break;
        }

        case NLM_STATS_LOG_NOTIFICATIONS_BUMPED: {
            SET_UNSIGNED_BIND(binding, get_num_log_discarded());
            break;
        }
    }

    INSTANCE_FOUND_OCTET_STRING_ROW(next_row, NOTIFICATION_LOG_STATS_OID,
        NLM_STATS_LOG_TABLE, column, (uint8_t *) notification_log_name,
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

MibModule *init_notification_log_stats_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, NLM_STATS_GLOBAL_NOTIFICATIONS_LOGGED,
        NLM_STATS_LOG_TABLE - NLM_STATS_GLOBAL_NOTIFICATIONS_LOGGED + 1,
        LEAF_SCALAR, LEAF_SCALAR, NLM_STATS_LOG_NOTIFICATIONS_BUMPED)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, NOTIFICATION_LOG_STATS_OID);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
