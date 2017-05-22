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

#include <arpa/inet.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/usm-dh-module.h"

#define SNMP_OID_USM_DH_PUBLIC      SNMP_OID_USM_DH,1,1
#define SNMP_OID_USM_DH_COMPLIANCE   SNMP_OID_USM_DH,2,1,1

static SysOREntry usm_dh_or_entry = {
    .or_id = {
        .subid = { SNMP_OID_USM_DH_COMPLIANCE },
        .len = OID_SEQ_LENGTH(SNMP_OID_USM_DH_COMPLIANCE)
    },
    .or_descr = "SNMP-USM-DH-OBJECTS-MIB - MIB module for Diffie-Hellman key exchange",
    .next = NULL
};

enum USMDHMIBObjects {
    USM_DH_PARAMETERS = 1,
    USM_DH_USER_KEY_TABLE = 2
};

enum USMDHUserTableColumns {
    USM_DH_USER_AUTH_KEY_CHANGE = 1,
    USM_DH_USER_OWN_AUTH_KEY_CHANGE = 2,
    USM_DH_USER_PRIV_KEY_CHANGE = 3,
    USM_DH_USER_OWN_PRIV_KEY_CHANGE = 4,
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    /* TODO */
    SET_OCTET_STRING_BIND(binding, NULL, 0);
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
    /* TODO */
    CHECK_INSTANCE_FOUND(next_row, NULL);

    switch (column) {
        case USM_DH_USER_AUTH_KEY_CHANGE: {
            /* TODO */
            break;
        }

        case USM_DH_USER_OWN_AUTH_KEY_CHANGE: {
            /* TODO */
            break;
        }

        case USM_DH_USER_PRIV_KEY_CHANGE: {
            /* TODO */
            break;
        }

        case USM_DH_USER_OWN_PRIV_KEY_CHANGE: {
            /* TODO */
            break;
        }

        default: {
            return GENERAL_ERROR;
        }
    }

    return NO_ERROR;
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *index, size_t index_len,
    SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_usm_dh_public_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, USM_DH_PARAMETERS,
        USM_DH_USER_KEY_TABLE - USM_DH_PARAMETERS + 1,
        LEAF_SCALAR, USM_DH_USER_OWN_PRIV_KEY_CHANGE)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_USM_DH_PUBLIC);
    SET_OR_ENTRY(module, &usm_dh_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
