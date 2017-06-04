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
#include <time.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-notification-log.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-core/snmp-date-time.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/notification-module.h"

#define NOTIFICATION_LOG_OID                 NOTIFICATION_LOG_MIB_OID,1,3
#define NOTIFICATION_LOG_CONFORMANCE_OID     NOTIFICATION_LOG_MIB_OID,3,1,1
#define NOTIFICATION_TADDRESS   "::1"

const char *const notification_log_name = "trap-log";

static SysOREntry notification_log_or_entry = {
    .or_id = {
        .subid = { NOTIFICATION_LOG_CONFORMANCE_OID },
        .len = OID_SEQ_LENGTH(NOTIFICATION_LOG_CONFORMANCE_OID)
    },
    .or_descr = "NOTIFICATION-LOG-MIB - MIB containing log of dispatched traps",
    .next = NULL
};

enum NotificationLogMIBObjects {
    NLM_LOG_TABLE = 1,
    NLM_LOG_VARIABLE_TABLE = 2
};

enum NotificationLogTableColumns {
    NLM_LOG_INDEX = 1,
    NLM_LOG_TIME = 2,
    NLM_LOG_DATE_AND_TIME = 3,
    NLM_LOG_ENGINE_ID = 4,
    NLM_LOG_ENGINE_TADDRESS = 5,
    NLM_LOG_ENGINE_TDOMAIN = 6,
    NLM_LOG_CONTEXT_ENGINE_ID = 7,
    NLM_LOG_CONTEXT_NAME = 8,
    NLM_LOG_NOTIFICATION_ID = 9
};

enum NotificationLogVariableTableColumns {
    NLM_LOG_VARIABLE_INDEX = 1,
    NLM_LOG_VARIABLE_ID = 2,
    NLM_LOG_VARIABLE_VALUE_TYPE = 3,
    NLM_LOG_VARIABLE_COUNTER32_VAL = 4,
    NLM_LOG_VARIABLE_UNSIGNED32_VAL = 5,
    NLM_LOG_VARIABLE_TIME_TICKS_VAL = 6,
    NLM_LOG_VARIABLE_INTEGER32_VAL = 7,
    NLM_LOG_VARIABLE_OCTET_STRING_VAL = 8,
    NLM_LOG_VARIABLE_IP_ADDRESS_VAL = 9,
    NLM_LOG_VARIABLE_OID_VAL = 10,
    NLM_LOG_VARIABLE_COUNTER64_VAL = 11,
    NLM_LOG_VARIABLE_OPAQUE_VAL = 12
};

static int get_var_type(SnmpVariableBinding *var)
{
    switch (var->type) {
        case SMI_TYPE_OCTET_STRING:
            return 6;
        case SMI_TYPE_OID:
            return 7;
        case SMI_TYPE_INTEGER_32:
            return 4;
        case SMI_TYPE_IP_ADDRESS:
            return 5;
        case SMI_TYPE_COUNTER_32:
            return 1;
        case SMI_TYPE_GAUGE_32:
            return 2;
        case SMI_TYPE_TIME_TICKS:
            return 3;
        case SMI_TYPE_OPAQUE:
            return 9;
        case SMI_TYPE_COUNTER_64:
            return 8;
        default:
            return -1;
    }
}

static int32_t get_entry_offset(SubOID *row, size_t row_len, int *var_idx, int next)
{
    int cmp = cmp_index_to_array((uint8_t *) notification_log_name,
        strlen(notification_log_name), row,
        min(row_len, strlen(notification_log_name) + 1));

    switch (cmp) {
        case -1: {
            if (!next)
                return -1;
            if (var_idx != NULL)
                *var_idx = -1;
            return 0;
            break;
        }

        case 0: {
            if (row_len < strlen(notification_log_name) + 1) {
                if (!next)
                    return -1;
                if (var_idx != NULL)
                    *var_idx = -1;
                return 0;
            }
            if (row_len < strlen(notification_log_name) + 2) {
                if (var_idx != NULL && !next)
                    return -1;
                if (var_idx != NULL)
                    *var_idx = -1;
                return row[strlen(notification_log_name) + 1];
            }
            if (!next && var_idx == NULL)
                return -1;
            if (var_idx != NULL)
                *var_idx = row[strlen(notification_log_name) + 2] - 1;
            return row[strlen(notification_log_name) + 1];
            break;
        }

        default: {
            return -1;
        }
    }
}

static int get_var_entry(SubOID *row, size_t row_len, LoggedTrapEntry *entry,
    int *var_idx, int column, int next)
{
    int type;
    switch (column) {
        case NLM_LOG_VARIABLE_COUNTER32_VAL:
            type = SMI_TYPE_COUNTER_32;
            break;

        case NLM_LOG_VARIABLE_UNSIGNED32_VAL:
            type = SMI_TYPE_GAUGE_32;
            break;

        case NLM_LOG_VARIABLE_TIME_TICKS_VAL:
            type = SMI_TYPE_TIME_TICKS;
            break;

        case NLM_LOG_VARIABLE_INTEGER32_VAL:
            type = SMI_TYPE_INTEGER_32;
            break;

        case NLM_LOG_VARIABLE_IP_ADDRESS_VAL:
            type = SMI_TYPE_IP_ADDRESS;
            break;

        case NLM_LOG_VARIABLE_OID_VAL:
            type = SMI_TYPE_OID;
            break;

        case NLM_LOG_VARIABLE_COUNTER64_VAL:
            type = SMI_TYPE_COUNTER_64;
            break;

        case NLM_LOG_VARIABLE_OCTET_STRING_VAL:
            type = SMI_TYPE_OCTET_STRING;
            break;

        case NLM_LOG_VARIABLE_OPAQUE_VAL:
            type = SMI_TYPE_OPAQUE;
            break;

        default:
            type = 0;
    }

    int var_offset = -1;
    int offset = get_entry_offset(row, row_len, &var_offset, next);
    if (offset == -1)
        return -1;
    if (get_trap_entry(offset, type, entry))
        return -1;
    if (next) {
        int run = 0;
        do {
            for (int i = var_offset + 1; i < entry->num_of_vars; i++) {
                if (type == 0 || entry->vars[i].type == type) {
                    *var_idx = i;
                    return 0;
                }
            }

            var_offset = -1;
            if (get_trap_entry(++offset, type, entry))
                return -1;
            run++;
        } while (run < 2);
        return -1;
    } else if (entry->index != offset) {
        return -1;
    } else {
        *var_idx = var_offset;
        return 0;
    }
}

static SnmpErrorStatus get_notification_log_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    LoggedTrapEntry entry;
    int32_t offset = get_entry_offset(row, row_len, NULL, next_row);
    if (offset != -1) {
        if (next_row)
            offset++;
        offset = get_trap_entry(offset, 0, &entry);
        if (offset != -1) {
            offset = next_row || entry.index == offset;
        }
    }
    CHECK_INT_FOUND(next_row, offset);

    switch (column) {
        case NLM_LOG_INDEX: {
            SET_GAUGE_BIND(binding, entry.index);
            break;
        }

        case NLM_LOG_TIME: {
            struct timespec system_time;
            if (clock_gettime(CLOCK_REALTIME, &system_time) == -1 ||
                system_time.tv_sec - get_uptime() > entry.timestamp / 1000) {
                SET_TIME_TICKS_BIND(binding, 0);
            } else {
                SET_TIME_TICKS_BIND(binding, 100 * entry.uptime);
            }
            break;
        }

        case NLM_LOG_DATE_AND_TIME: {
            if (encode_date_time(entry.timestamp, binding))
                return GENERAL_ERROR;
            break;
        }

        case NLM_LOG_ENGINE_ID:
        case NLM_LOG_CONTEXT_ENGINE_ID: {
            uint8_t *engine_id;
            size_t engine_id_len = get_engine_id(&engine_id);
            SET_OCTET_STRING_RESULT(binding,
                memdup(engine_id, engine_id_len), engine_id_len);
            break;
        }

        case NLM_LOG_ENGINE_TADDRESS: {
            SET_OCTET_STRING_RESULT(binding, strdup(NOTIFICATION_TADDRESS),
                strlen(NOTIFICATION_TADDRESS));
            break;
        }

        case NLM_LOG_ENGINE_TDOMAIN: {
            SET_OID_BIND(binding, SNMP_OID_SNMPV2,1,1);
            break;
        }
        case NLM_LOG_CONTEXT_NAME: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case NLM_LOG_NOTIFICATION_ID: {
            COPY_OID_BIND(binding, &entry.trap_type);
            break;
        }
    }

    if (next_row) {
        SET_OID(binding->oid, NOTIFICATION_LOG_OID, NLM_LOG_TABLE, 1, column);
        fill_row_index_string(&binding->oid, (uint8_t *) notification_log_name,
            strlen(notification_log_name));
        binding->oid.subid[binding->oid.len++] = entry.index;
    }
    return NO_ERROR;
}

static SnmpErrorStatus get_notification_log_var_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    LoggedTrapEntry entry;
    int32_t var_idx = -1;
    int found = get_var_entry(row, row_len, &entry, &var_idx, column, next_row);
    CHECK_INT_FOUND(next_row, found);

    switch (column) {
        case NLM_LOG_VARIABLE_INDEX: {
            SET_GAUGE_BIND(binding, var_idx + 1);
            break;
        }

        case NLM_LOG_VARIABLE_ID: {
            COPY_OID_BIND(binding, &entry.vars[var_idx].oid);
            break;
        }

        case NLM_LOG_VARIABLE_VALUE_TYPE: {
            SET_INTEGER_BIND(binding, get_var_type(&entry.vars[var_idx]));
            break;
        }

        case NLM_LOG_VARIABLE_COUNTER32_VAL:
        case NLM_LOG_VARIABLE_UNSIGNED32_VAL:
        case NLM_LOG_VARIABLE_TIME_TICKS_VAL:
        case NLM_LOG_VARIABLE_INTEGER32_VAL:
        case NLM_LOG_VARIABLE_IP_ADDRESS_VAL: {
            binding->type = entry.vars[var_idx].type;
            memcpy(&binding->value.integer,
                &entry.vars[var_idx].value.integer, sizeof(int32_t));
            break;
        }

        case NLM_LOG_VARIABLE_OID_VAL: {
            COPY_OID_BIND(binding, &entry.vars[var_idx].value.oid);
            break;
        }

        case NLM_LOG_VARIABLE_COUNTER64_VAL: {
            SET_UNSIGNED64_BIND(binding, entry.vars[var_idx].value.counter64);
            break;
        }

        case NLM_LOG_VARIABLE_OCTET_STRING_VAL:
        case NLM_LOG_VARIABLE_OPAQUE_VAL: {
            binding->type = entry.vars[var_idx].type;
            binding->value.octet_string.len =
                entry.vars[var_idx].value.octet_string.len;
            binding->value.octet_string.octets =
                    memdup(entry.vars[var_idx].value.octet_string.octets,
                            entry.vars[var_idx].value.octet_string.len);
            if (binding->value.octet_string.octets == NULL)
                return GENERAL_ERROR;
            break;
        }
    }

    if (next_row) {
        SET_OID(binding->oid, NOTIFICATION_LOG_OID, NLM_LOG_VARIABLE_TABLE, 1, column);
        fill_row_index_string(&binding->oid, (uint8_t *) notification_log_name,
            strlen(notification_log_name));
        binding->oid.subid[binding->oid.len++] = entry.index;
        binding->oid.subid[binding->oid.len++] = var_idx + 1;
    }
    return NO_ERROR;
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    switch (id) {
        case NLM_LOG_TABLE: {
            return get_notification_log_table(column, row, row_len,
                binding, next_row);
        }

        case NLM_LOG_VARIABLE_TABLE: {
            return get_notification_log_var_table(column, row, row_len,
                binding, next_row);
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

MibModule *init_notification_log_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, NLM_LOG_TABLE,
        NLM_LOG_VARIABLE_TABLE - NLM_LOG_TABLE + 1,
        NLM_LOG_NOTIFICATION_ID, NLM_LOG_VARIABLE_OPAQUE_VAL)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, NOTIFICATION_LOG_OID);
    SET_OR_ENTRY(module, &notification_log_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
