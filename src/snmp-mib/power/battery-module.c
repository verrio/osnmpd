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
#include "snmp-core/snmp-date-time.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/single-table-module.h"
#include "snmp-mib/power/battery-module.h"
#include "snmp-mib/power/power-cache.h"

#define BATTERY_MIB_COMPLIANCE_OID  SNMP_OID_BATTERY_MIB,2,1,1

static SysOREntry battery_or_entry = {
    .or_id = {
        .subid = { BATTERY_MIB_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(BATTERY_MIB_COMPLIANCE_OID)
    },
    .or_descr = "BATTERY-MIB - MIB module defining a set of objects "
            "for monitoring batteries",
    .next = NULL
};

enum BatteryTableColumns {
    BATTERY_IDENTIFIER = 1,
    BATTERY_FIRMWARE_VERSION = 2,
    BATTERY_TYPE = 3,
    BATTERY_TECHNOLOGY = 4,
    BATTERY_DESIGN_VOLTAGE = 5,
    BATTERY_NUMBER_OF_CELLS = 6,
    BATTERY_DESIGN_CAPACITY = 7,
    BATTERY_MAX_CHARGING_CURRENT = 8,
    BATTERY_TRICKLE_CHARGING_CURRENT = 9,
    BATTERY_ACTUAL_CAPACITY = 10,
    BATTERY_CHARGING_CYCLE_COUNT = 11,
    BATTERY_LAST_CHARGING_CYCLE_TIME = 12,
    BATTERY_CHARGING_OPER_STATE = 13,
    BATTERY_CHARGING_ADMIN_STATE = 14,
    BATTERY_ACTUAL_CHARGE = 15,
    BATTERY_ACTUAL_VOLTAGE = 16,
    BATTERY_ACTUAL_CURRENT = 17,
    BATTERY_TEMPERATURE = 18,
    BATTERY_ALARM_LOW_CHARGE = 19,
    BATTERY_ALARM_LOW_VOLTAGE = 20,
    BATTERY_ALARM_LOW_CAPACITY = 21,
    BATTERY_ALARM_HIGH_CYCLECOUNT = 22,
    BATTERY_ALARM_HIGH_TEMPERATURE = 23,
    BATTERY_ALARM_LOW_TEMPERATURE = 24,
    BATTERY_CELL_IDENTIFIER = 25
};

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    BatteryEntry *entry = NULL;
    for (BatteryEntry *e = get_battery_list(); e != NULL; e = e->next) {
        if (next_row) {
            if (row_len < 1 || row[0] < e->index) {
                entry = e;
                break;
            }
        } else if (row_len == 1 && row[0] == e->index) {
            entry = e;
            break;
        }
    }

    CHECK_INSTANCE_FOUND(next_row, entry);

    switch (column) {
        case BATTERY_IDENTIFIER: {
            SET_OCTET_STRING_RESULT(binding,
                strndup(entry->identifier, sizeof(entry->identifier)),
                strnlen(entry->identifier, sizeof(entry->identifier)));
            break;
        }

        case BATTERY_FIRMWARE_VERSION: {
            SET_OCTET_STRING_RESULT(binding,
                strndup(entry->fw_version, sizeof(entry->fw_version)),
                strnlen(entry->fw_version, sizeof(entry->fw_version)));
            break;
        }

        case BATTERY_TYPE: {
            SET_INTEGER_BIND(binding, entry->type);
            break;
        }

        case BATTERY_TECHNOLOGY: {
            SET_GAUGE_BIND(binding, entry->technology);
            break;
        }

        case BATTERY_DESIGN_VOLTAGE: {
            SET_GAUGE_BIND(binding, entry->design_voltage);
            break;
        }

        case BATTERY_NUMBER_OF_CELLS: {
            SET_GAUGE_BIND(binding, entry->num_cells);
            break;
        }

        case BATTERY_DESIGN_CAPACITY: {
            SET_GAUGE_BIND(binding, entry->design_capacity);
            break;
        }

        case BATTERY_MAX_CHARGING_CURRENT: {
            SET_GAUGE_BIND(binding, entry->charging_cycle_count);
            break;
        }

        case BATTERY_TRICKLE_CHARGING_CURRENT: {
            SET_GAUGE_BIND(binding, entry->trickle_charging_current);
            break;
        }

        case BATTERY_ACTUAL_CAPACITY: {
            SET_GAUGE_BIND(binding, entry->actual_capacity);
            break;
        }

        case BATTERY_CHARGING_CYCLE_COUNT: {
            SET_GAUGE_BIND(binding, entry->charging_cycle_count);
            break;
        }

        case BATTERY_LAST_CHARGING_CYCLE_TIME: {
            if (encode_date_time(entry->last_charging_cycle_time, binding)) {
                return GENERAL_ERROR;
            }
            break;
        }

        case BATTERY_CHARGING_OPER_STATE: {
            SET_INTEGER_BIND(binding, entry->oper_state);
            break;
        }

        case BATTERY_CHARGING_ADMIN_STATE: {
            SET_INTEGER_BIND(binding, entry->admin_state);
            break;
        }

        case BATTERY_ACTUAL_CHARGE: {
            SET_GAUGE_BIND(binding, entry->actual_charge);
            break;
        }

        case BATTERY_ACTUAL_VOLTAGE: {
            SET_GAUGE_BIND(binding, entry->actual_voltage);
            break;
        }

        case BATTERY_ACTUAL_CURRENT: {
            SET_INTEGER_BIND(binding, entry->actual_current);
            break;
        }

        case BATTERY_TEMPERATURE: {
            SET_INTEGER_BIND(binding, entry->temperature);
            break;
        }

        case BATTERY_ALARM_LOW_CHARGE:
        case BATTERY_ALARM_LOW_VOLTAGE:
        case BATTERY_ALARM_LOW_CAPACITY:
        case BATTERY_ALARM_HIGH_CYCLECOUNT: {
            SET_GAUGE_BIND(binding, 0);
            break;
        }

        case BATTERY_ALARM_HIGH_TEMPERATURE:
        case BATTERY_ALARM_LOW_TEMPERATURE: {
            SET_INTEGER_BIND(binding, 0x7fffffff);
            break;
        }

        case BATTERY_CELL_IDENTIFIER: {
            SET_OCTET_STRING_RESULT(binding, strndup(entry->cell_identifier,
                sizeof(entry->cell_identifier)), strnlen(entry->cell_identifier,
                sizeof(entry->cell_identifier)));
            break;
        }

        default: {
            return GENERAL_ERROR;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_BATTERY_OBJECTS, 1, column, entry->index)
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

MibModule *init_battery_module(void)
{
    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module,
        BATTERY_IDENTIFIER, BATTERY_CELL_IDENTIFIER)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_BATTERY_OBJECTS, 1, 1);
    SET_OR_ENTRY(module, &battery_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
