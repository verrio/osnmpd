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

#define UPS_MIB_COMPLIANCE_OID  SNMP_OID_MIB2,33,3,1,3

static SysOREntry ups_or_entry = {
    .or_id = {
        .subid = { UPS_MIB_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(UPS_MIB_COMPLIANCE_OID)
    },
    .or_descr = "UPS-MIB - MIB module defining a set of objects "
            "for uninterruptible power supplies",
    .next = NULL
};

enum UPSIdentTableColumns {
    UPS_IDENT_MANUFACTURER = 1,
    UPS_IDENT_MODEL = 2,
    UPS_IDENT_UPS_SOFTWARE_VERSION = 3,
    UPS_IDENT_AGENT_SOFTWARE_VERSION = 4,
    UPS_IDENT_NAME = 5,
    UPS_IDENT_ATTACHED_DEVICES = 6
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case UPS_IDENT_MANUFACTURER: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_IDENT_MODEL: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_IDENT_UPS_SOFTWARE_VERSION: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_IDENT_AGENT_SOFTWARE_VERSION: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_IDENT_NAME: {
            /* TODO */
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case UPS_IDENT_ATTACHED_DEVICES: {
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

MibModule *init_ups_ident_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, UPS_IDENT_MANUFACTURER,
            UPS_IDENT_ATTACHED_DEVICES - UPS_IDENT_MANUFACTURER + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_UPS_IDENT_OBJECTS);
    SET_OR_ENTRY(module, &ups_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
