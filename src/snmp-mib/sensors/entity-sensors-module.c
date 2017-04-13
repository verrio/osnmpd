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
#include <sys/utsname.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/single-table-module.h"
#include "snmp-mib/sensors/entity-sensors-module.h"
#include "snmp-mib/sensors/sensor-cache.h"

#define ENTITY_SENSORS_MIB_COMPLIANCE_OID   SNMP_OID_MIB2,99,3,1,1

static SysOREntry entity_sensors_or_entry = {
    .or_id = {
        .subid = { ENTITY_SENSORS_MIB_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(ENTITY_SENSORS_MIB_COMPLIANCE_OID)
    },
    .or_descr = "ENTITY-SENSORS-MIB - MIB module for physical sensors",
    .next = NULL
};

enum EntitySensorsTableColumns {
    ENT_PHY_SENSOR_TYPE = 1,
    ENT_PHY_SENSOR_SCALE = 2,
    ENT_PHY_SENSOR_PRECISION = 3,
    ENT_PHY_SENSOR_VALUE = 4,
    ENT_PHY_SENSOR_OPER_STATUS = 5,
    ENT_PHY_SENSOR_UNITS_DISPLAY = 6,
    ENT_PHY_SENSOR_VALUE_TIME_STAMP = 7,
    ENT_PHY_SENSOR_VALUE_UPDATE_RATE = 8
};

static EntitySensor *get_sensor(SubOID *row, size_t row_len, int next)
{
    EntitySensorList *sensors = get_sensor_cache();
    if (sensors == NULL || (!next && row_len != 1)) {
        return NULL;
    }

    for (int i = 0; i < sensors->len; i++) {
        if (next) {
            if (row_len < 1 || row[0] < sensors->list[i]->entity_index) {
                return sensors->list[i];
            }
        } else if (row[0] == sensors->list[i]->entity_index) {
            return sensors->list[i];
        }
    }

    return NULL;
}

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    EntitySensor *sensor = get_sensor(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, sensor);

    switch (column) {
        case ENT_PHY_SENSOR_TYPE: {
            SET_INTEGER_BIND(binding, sensor->data_type);
            break;
        }

        case ENT_PHY_SENSOR_SCALE: {
            SET_INTEGER_BIND(binding, sensor->scale);
            break;
        }

        case ENT_PHY_SENSOR_PRECISION: {
            SET_INTEGER_BIND(binding, sensor->precision);
            break;
        }

        case ENT_PHY_SENSOR_VALUE: {
            update_sensor(sensor);
            SET_INTEGER_BIND(binding, sensor->value);
            break;
        }

        case ENT_PHY_SENSOR_OPER_STATUS: {
            update_sensor(sensor);
            SET_INTEGER_BIND(binding, sensor->status);
            break;
        }

        case ENT_PHY_SENSOR_UNITS_DISPLAY: {
            SET_OCTET_STRING_RESULT(binding,
                strdup(sensor->description), strlen(sensor->description));
            break;
        }

        case ENT_PHY_SENSOR_VALUE_TIME_STAMP: {
            SET_TIME_TICKS_BIND(binding, 100 * get_uptime());
            break;
        }

        case ENT_PHY_SENSOR_VALUE_UPDATE_RATE: {
            /* on-demand */
            SET_GAUGE_BIND(binding, 0);
            break;
        }

        default: {
            return GENERAL_ERROR;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_SENSORS_OBJECTS, 1,
            column, sensor->entity_index)
}

DEF_METHOD(set_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *index, size_t index_len, SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleTableMibModule)
{
    finish_sensor_cache();
    finish_single_table_module(this);
}

MibModule *init_entity_sensors_module(void)
{
    if (init_sensor_cache()) {
        syslog(LOG_WARNING, "failed to initialise sensor cache");
        return NULL;
    }

    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module,
        ENT_PHY_SENSOR_TYPE, ENT_PHY_SENSOR_VALUE_UPDATE_RATE)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_SENSORS_OBJECTS,1,1);
    SET_OR_ENTRY(module, &entity_sensors_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
