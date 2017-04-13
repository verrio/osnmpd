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

#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-crypto.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/usm-users-module.h"

#define SNMP_OID_USM_USERS_MIB   SNMP_OID_USM_MIB,1,2

/* privacy and authentication protocol identifiers */
#define USM_AES_CFB_128_PROTOCOL    SNMP_OID_SNMPMODULES,10,1,2,4
#define USM_NO_PRIV_PROTOCOL        SNMP_OID_SNMPMODULES,10,1,2,1
#define USM_HMAC_SHA_1_96_PROTOCOL  SNMP_OID_SNMPMODULES,10,1,1,3
#define USM_NO_AUTH_PROTOCOL        SNMP_OID_SNMPMODULES,2,1,1,1

enum USMUsersMIBObjects {
    USM_USER_SPIN_LOCK = 1,
    USM_USER_TABLE = 2
};

enum USMUserTableColumns {
    USM_USER_ENGINE_ID = 1,
    USM_USER_NAME = 2,
    USM_USER_SECURITY_NAME = 3,
    USM_USER_CLONE_FROM = 4,
    USM_USER_AUTH_PROTOCOL = 5,
    USM_USER_AUTH_KEY_CHANGE = 6,
    USM_USER_OWN_AUTH_KEY_CHANGE = 7,
    USM_USER_PRIV_PROTOCOL = 8,
    USM_USER_PRIV_KEY_CHANGE = 9,
    USM_USER_OWN_PRIV_KEY_CHANGE = 10,
    USM_USER_PUBLIC = 11,
    USM_USER_STORAGE_TYPE = 12,
    USM_USER_STATUS = 13
};

/* table rows */
static const char *user_names[] = { "ADMIN", "PUBLIC", "READ_ONLY", "READ_WRITE" };
static const SnmpUserSlot user_slots[] = { USER_ADMIN, USER_PUBLIC,
        USER_READ_ONLY, USER_READ_WRITE };

static int get_user_row(SubOID *row, size_t row_len, int next_row)
{
    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);

    /* first index contains engine id */
    switch (cmp_index_to_array(engine_id, engine_id_len, row,
            min(engine_id_len + 1, row_len))) {
        case -1: {
            return next_row ? 0 : -1;
        }

        case 1: {
            return -1;
        }
    }

    if (row_len < engine_id_len + 1) {
        return next_row ? 0 : -1;
    }

    /* second index contains user name */
    return bsearch_string_indices(user_names,
            sizeof(user_names) / sizeof(char *), row + engine_id_len + 1,
            row_len - engine_id_len - 1, next_row);
}

static UserConfiguration *get_row_entry(int row)
{
    if (row == -1) {
        return NULL;
    } else {
        return get_user_configuration(user_slots[row]);
    }
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    /* spinlock unused */
    SET_INTEGER_BIND(binding, 0);
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
    int user_row = get_user_row(row, row_len, next_row);
    UserConfiguration *entry = get_row_entry(user_row);
    CHECK_INSTANCE_FOUND(next_row, entry);

    switch (column) {
        case USM_USER_ENGINE_ID: {
            uint8_t *engine_id;
            size_t engine_id_len = get_engine_id(&engine_id);
            SET_OCTET_STRING_RESULT(binding,
                    memdup(engine_id, engine_id_len), engine_id_len);
            break;
        }

        case USM_USER_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(user_names[user_row]),
                    strlen(user_names[user_row]));
            break;
        }

        case USM_USER_SECURITY_NAME: {
            SET_OCTET_STRING_RESULT(binding,
                    strdup(entry->name), strlen(entry->name));
            break;
        }

        case USM_USER_CLONE_FROM: {
            SET_OID_BIND(binding, 0, 0);
            break;
        }

        case USM_USER_AUTH_PROTOCOL: {
            if (entry->security_level > NO_AUTH_NO_PRIV) {
                SET_OID_BIND(binding, USM_HMAC_SHA_1_96_PROTOCOL);
            } else {
                SET_OID_BIND(binding, USM_NO_AUTH_PROTOCOL);
            }
            break;
        }

        case USM_USER_PRIV_PROTOCOL: {
            if (entry->security_level > AUTH_NO_PRIV) {
                SET_OID_BIND(binding, USM_AES_CFB_128_PROTOCOL);
            } else {
                SET_OID_BIND(binding, USM_NO_PRIV_PROTOCOL);
            }
            break;
        }

        case USM_USER_AUTH_KEY_CHANGE:
        case USM_USER_OWN_AUTH_KEY_CHANGE:
        case USM_USER_PRIV_KEY_CHANGE:
        case USM_USER_OWN_PRIV_KEY_CHANGE:
        case USM_USER_PUBLIC: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case USM_USER_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case USM_USER_STATUS: {
            /* active/notInService */
            SET_INTEGER_BIND(binding, entry->enabled ? 1 : 2);
            break;
        }
    }

    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);
    INSTANCE_FOUND_OCTET_STRING_ROW2(next_row, SNMP_OID_USM_USERS_MIB, id, \
        column, engine_id, engine_id_len, (uint8_t *) user_names[user_row], \
        strlen(user_names[user_row]));
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int dry_run)
{
    int user_row = get_user_row(row, row_len, 0);
    return user_row == -1 ? NO_CREATION : NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_usm_users_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, USM_USER_SPIN_LOCK,
            USM_USER_TABLE - USM_USER_SPIN_LOCK + 1, LEAF_SCALAR, USM_USER_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_USM_USERS_MIB);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
