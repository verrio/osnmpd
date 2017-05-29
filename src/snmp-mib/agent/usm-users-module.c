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
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-incoming.h"
#include "snmp-agent/agent-notification.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-crypto.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/usm-users-module.h"

#define SNMP_OID_USM_USERS_MIB   SNMP_OID_USM_MIB,1,2

/* privacy and authentication protocol identifiers */
#define USM_AES_CFB_128_PROTOCOL      SNMP_OID_SNMPMODULES,10,1,2,4
#define USM_AES_CFB_256_PROTOCOL      SNMP_OID_CISCO,12,6,1,2
#define USM_NO_PRIV_PROTOCOL          SNMP_OID_SNMPMODULES,10,1,2,1
#define USM_HMAC_96_SHA_1_PROTOCOL    SNMP_OID_SNMPMODULES,10,1,1,3
#define USM_HMAC_192_SHA256_PROTOCOL  SNMP_OID_SNMPMODULES,10,1,1,5
#define USM_NO_AUTH_PROTOCOL          SNMP_OID_SNMPMODULES,10,1,1,1

#ifdef USE_LEGACY_CRYPTO
#define USM_AUTH_PROTOCOL             USM_HMAC_96_SHA_1_PROTOCOL
#define USM_PRIV_PROTOCOL             USM_AES_CFB_128_PROTOCOL
#else
#define USM_AUTH_PROTOCOL             USM_HMAC_192_SHA256_PROTOCOL
#define USM_PRIV_PROTOCOL             USM_AES_CFB_256_PROTOCOL
#endif

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

static const char *sec_names[] = { "PUBLIC", "READ_ONLY", "READ_WRITE", "ADMIN" };

UserConfiguration *get_user_row(SubOID *row, size_t row_len, int next_row)
{
    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);
    SubOID *user_offset = row + engine_id_len + 1;
    size_t user_len = row_len < engine_id_len + 1 ?
            0 : row_len - engine_id_len - 1;

    /* first index contains engine id */
    switch (cmp_index_to_array(engine_id, engine_id_len, row,
            min(engine_id_len + 1, row_len))) {
        case -1: {
            if (next_row) {
                user_len = 0;
            } else {
                return NULL;
            }
            break;
        }

        case 1: {
            return NULL;
        }
    }

    /* second index contains user name */
    UserConfiguration *conf = NULL;

    for (int i = 0; i < NUMBER_OF_USER_SLOTS; i++) {
        UserConfiguration *c = get_user_configuration(i);
        if (c == NULL || c->name == NULL)
            continue;
        size_t name_len = strlen(c->name);
        switch (cmp_index_to_array((uint8_t *) c->name, name_len, user_offset, user_len)) {
            case 0: {
                if (!next_row)
                    return c;
                break;
            }

            case -1: {
                if (next_row &&
                    (conf == NULL || (strlen(c->name) < strlen(conf->name)) ||
                    ((strlen(c->name) == strlen(conf->name)) &&
                    (strcmp(c->name, conf->name) < 0)))) {
                    conf = c;
                }
                break;
            }
        }
    }

    return conf;
}

static SnmpErrorStatus set_user_active(UserConfiguration *user, int enabled)
{
    user->enabled = enabled;
    if (set_user_configuration(user))
        return GENERAL_ERROR;
    if (write_configuration())
        return GENERAL_ERROR;
    update_incoming_keyset();
    return NO_ERROR;
}

static SnmpErrorStatus set_user_name(UserConfiguration *user,
        const SnmpVariableBinding *binding, int dry_run)
{
    if (dry_run) {
        if (binding->type != SMI_TYPE_OCTET_STRING)
            return WRONG_TYPE;
        if (binding->value.octet_string.len < 1 ||
            binding->value.octet_string.len > 0x40)
            return WRONG_LENGTH;
        if (is_utf8(binding->value.octet_string.octets,
                binding->value.octet_string.len))
            return WRONG_ENCODING;
        for (int i = 0; i < NUMBER_OF_USER_SLOTS; i++) {
            if (i == user->user)
                continue;
            UserConfiguration *config = get_user_configuration(i);
            if (config != NULL && config->name != NULL &&
                strlen(config->name) == binding->value.octet_string.len &&
                !strncmp(config->name, (char *) binding->value.octet_string.octets,
                        binding->value.octet_string.len))
                return WRONG_VALUE;
        }
    } else {
        UserConfiguration new_config;
        memcpy(&new_config, user, sizeof(UserConfiguration));
        binding->value.octet_string.octets[binding->value.octet_string.len] = '\0';
        new_config.name = (char *) binding->value.octet_string.octets;
        if (set_user_configuration(&new_config))
            return GENERAL_ERROR;
        if (write_configuration())
            return GENERAL_ERROR;
        update_incoming_keyset();
        refresh_notification_handler_state();
    }

    return NO_ERROR;
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
    return NO_ERROR;
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    UserConfiguration *user = get_user_row(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, user);

    switch (column) {
        case USM_USER_ENGINE_ID: {
            uint8_t *engine_id;
            size_t engine_id_len = get_engine_id(&engine_id);
            SET_OCTET_STRING_RESULT(binding,
                    memdup(engine_id, engine_id_len), engine_id_len);
            break;
        }

        case USM_USER_NAME: {
            if (user->name == NULL) {
                SET_OCTET_STRING_BIND(binding, NULL, 0);
            } else {
                SET_OCTET_STRING_RESULT(binding, strdup(user->name), strlen(user->name));
            }
            break;
        }

        case USM_USER_SECURITY_NAME: {
            SET_OCTET_STRING_RESULT(binding,
                    strdup(sec_names[user->user]), strlen(sec_names[user->user]));
            break;
        }

        case USM_USER_CLONE_FROM: {
            SET_OID_BIND(binding, 0, 0);
            break;
        }

        case USM_USER_AUTH_PROTOCOL: {
            if (user->security_level > NO_AUTH_NO_PRIV) {
                SET_OID_BIND(binding, USM_AUTH_PROTOCOL);
            } else {
                SET_OID_BIND(binding, USM_NO_AUTH_PROTOCOL);
            }
            break;
        }

        case USM_USER_PRIV_PROTOCOL: {
            if (user->security_level > AUTH_NO_PRIV) {
                SET_OID_BIND(binding, USM_PRIV_PROTOCOL);
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
            /* permanent */
            SET_INTEGER_BIND(binding, 4);
            break;
        }

        case USM_USER_STATUS: {
            /* active/notInService */
            SET_INTEGER_BIND(binding, user->enabled ? 1 : 2);
            break;
        }
    }

    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);
    INSTANCE_FOUND_OCTET_STRING_ROW2(next_row, SNMP_OID_USM_USERS_MIB, id, \
        column, engine_id, engine_id_len, (uint8_t *) user->name, \
        user->name == NULL ? 0 : strlen(user->name));
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int dry_run)
{
    UserConfiguration *user = get_user_row(row, row_len, 0);
    if (user == NULL)
        return NO_CREATION;

    switch (column) {
        case USM_USER_NAME:
        case USM_USER_SECURITY_NAME: {
            return set_user_name(user, binding, dry_run);
        }

        case USM_USER_AUTH_KEY_CHANGE:
        case USM_USER_OWN_AUTH_KEY_CHANGE:
        case USM_USER_PRIV_KEY_CHANGE:
        case USM_USER_OWN_PRIV_KEY_CHANGE:
        case USM_USER_PUBLIC: {
            syslog(LOG_WARNING, "Change user passwords in USM table disallowed."
                    "Please use D-H table instead.");
            return NOT_WRITABLE;
        }

        case USM_USER_STATUS: {
            if (dry_run) {
                if (binding->type != SMI_TYPE_INTEGER_32)
                    return WRONG_TYPE;
                if (binding->value.integer != 1 && binding->value.integer != 2)
                    return WRONG_VALUE;
            } else if (set_user_active(user, binding->value.integer == 1)) {
                return GENERAL_ERROR;
            }
            break;
        }

        default: {
            return NOT_WRITABLE;
        }
    }

    return NO_ERROR;
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
