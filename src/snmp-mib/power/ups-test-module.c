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

enum UPSTestObjects {
    UPS_TEST_ID = 1,
    UPS_TEST_SPIN_LOCK = 2,
    UPS_TEST_RESULTS_SUMMARY = 3,
    UPS_TEST_RESULTS_DETAIL = 4,
    UPS_TEST_START_TIME = 5,
    UPS_TEST_ELAPSED_TIME = 6
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case UPS_TEST_ID: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_TEST_SPIN_LOCK: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_TEST_RESULTS_SUMMARY: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_TEST_RESULTS_DETAIL: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_TEST_START_TIME: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_TEST_ELAPSED_TIME: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
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

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_ups_test_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, UPS_TEST_ID,
            UPS_TEST_ELAPSED_TIME - UPS_TEST_ID + 1, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_UPS_TEST_OBJECTS);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
