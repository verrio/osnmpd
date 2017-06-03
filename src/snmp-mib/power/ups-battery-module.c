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
#include "snmp-mib/power/ups-module.h"
#include "snmp-mib/power/power-cache.h"

enum UPSBatteryTableColumns {
    UPS_BATTERY_STATUS = 1,
    UPS_SECONDS_ON_BATTERY = 2,
    UPS_ESTIMATED_MINUTES_REMAINING = 3,
    UPS_ESTIMATED_CHARGE_REMAINING = 4,
    UPS_BATTERY_VOLTAGE = 5,
    UPS_BATTERY_CURRENT = 6,
    UPS_BATTERY_TEMPERATURE = 7
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    UPSEntry *ups = get_ups_info();

    if (ups == NULL) {
        SET_INTEGER_BIND(binding, 0);
    } else {
        switch (id) {
            case UPS_BATTERY_STATUS: {
                SET_INTEGER_BIND(binding, ups->status);
                break;
            }

            case UPS_SECONDS_ON_BATTERY: {
                SET_INTEGER_BIND(binding, ups->seconds_on_battery);
                break;
            }

            case UPS_ESTIMATED_MINUTES_REMAINING: {
                SET_INTEGER_BIND(binding, ups->minutes_remaining);
                break;
            }

            case UPS_ESTIMATED_CHARGE_REMAINING: {
                SET_INTEGER_BIND(binding, ups->charge_remaining);
                break;
            }

            case UPS_BATTERY_VOLTAGE: {
                SET_INTEGER_BIND(binding, ups->voltage);
                break;
            }

            case UPS_BATTERY_CURRENT: {
                SET_INTEGER_BIND(binding, ups->current);
                break;
            }

            case UPS_BATTERY_TEMPERATURE: {
                SET_INTEGER_BIND(binding, ups->temperature);
                break;
            }
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

MibModule *init_ups_battery_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, UPS_BATTERY_STATUS,
            UPS_BATTERY_TEMPERATURE - UPS_BATTERY_STATUS + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_UPS_BATTERY_OBJECTS);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
