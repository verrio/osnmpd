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
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-incoming.h"
#include "snmp-agent/agent-notification.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-crypto.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/usm-users-module.h"
#include "snmp-mib/agent/usm-dh-module.h"

#define SNMP_OID_USM_DH_PUBLIC       SNMP_OID_USM_DH,1,1
#define SNMP_OID_USM_DH_COMPLIANCE   SNMP_OID_USM_DH,2,1,1

static SysOREntry usm_dh_or_entry = {
    .or_id = {
        .subid = { SNMP_OID_USM_DH_COMPLIANCE },
        .len = OID_SEQ_LENGTH(SNMP_OID_USM_DH_COMPLIANCE)
    },
    .or_descr = "SNMP-USM-DH-OBJECTS-MIB - MIB module for Diffie-Hellman key exchange",
    .next = NULL
};

/* Diffie-Hellman group parameters */
static const uint8_t dh_p[] = { USM_DH_PARAM_PRIME };
static const uint8_t dh_g = USM_DH_PARAM_GENERATOR;
static const size_t dh_pub_key_len = sizeof(dh_p) / sizeof(uint8_t);
static DH *user_auth_keys[NUMBER_OF_USER_SLOTS - 1] = {0};
static DH *user_priv_keys[NUMBER_OF_USER_SLOTS - 1] = {0};

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

static DH *init_dh_st(void)
{
    DH *dh = DH_new();
    if (dh == NULL)
        return NULL;

    dh->p = BN_bin2bn(dh_p, sizeof(dh_p), NULL);
    dh->g = BN_bin2bn(&dh_g, 1, NULL);
    if (dh->p == NULL || dh->g == NULL) {
        DH_free(dh);
        return NULL;
    }

    return dh;
}

static DH *get_dh_key(SnmpUserSlot user, int auth)
{
    if (user == USER_PUBLIC)
        return NULL;

    DH *key = auth ? user_auth_keys[user-1] : user_priv_keys[user-1];

    if (key == NULL) {
        key = init_dh_st();
        if (key == NULL)
            return NULL;

        if (DH_generate_key(key) == 0) {
            syslog(LOG_ERR, "failed to generate DH keypair : %s",
                ERR_error_string(ERR_get_error(), NULL));
            DH_free(key);
            return NULL;
        }

        if (auth) {
            user_auth_keys[user-1] = key;
        } else {
            user_priv_keys[user-1] = key;
        }
    }

    return key;
}

/**
 * get_params_encoded - returns DER encoded D-H parameters.
 *
 * @enc_len OUT - length of encoded parameters;
 * @return pointer to D-H parameters (freed by caller), NULL on failure.
 */
static uint8_t *get_params_encoded(size_t *enc_len)
{
    uint8_t *result = NULL;
    DH *dh = init_dh_st();
    if (dh == NULL)
        goto err;

    int len = i2d_DHparams(dh, NULL);
    if (len <= 0)
        goto err;
    *enc_len = len;
    result = malloc(len);
    if (result == NULL)
        goto err;
    uint8_t *res = result;
    if (i2d_DHparams(dh, &res) < 0) {
        free(result);
        result = NULL;
    }
    goto fin;
err:
    syslog(LOG_ERR, "failed to initialize DH parameters : %s",
            ERR_error_string(ERR_get_error(), NULL));
fin:
    DH_free(dh);
    return result;
}

/**
 * get_pub_key_encoded - returns DER encoded public key for given user.
 *
 * @user	IN  - user slot
 * @auth	IN  - set to 0 if privacy keypair is requested
 * @enc_len OUT - length of encoded public key;
 * @return pointer to public key (freed by caller), NULL on failure.
 */
static uint8_t *get_pub_key_encoded(SnmpUserSlot user, int auth, size_t *enc_len)
{
    DH *key = get_dh_key(user, auth);
    if (key == NULL)
        return NULL;

    int key_len = BN_num_bytes(key->pub_key);
    if (key_len <= 0)
        return NULL;

    uint8_t *enc = malloc(key_len);
    if(enc == NULL)
        return NULL;
    *enc_len = key_len;
    if (BN_bn2bin(key->pub_key, enc) != key_len)
        return NULL;
    return enc;
}

/**
 * validate_pub_key - validates the given public key for given user.
 *
 * @user    IN  - user slot
 * @auth    IN  - set to 0 if privacy keypair is requested
 * @pub_key IN  - user provided public key
 * @return result of validation.
 */
static SnmpErrorStatus validate_pub_key(SnmpUserSlot user, int auth,
        SnmpVariableBinding *pub_key)
{
    if (pub_key->type != SMI_TYPE_OCTET_STRING)
        return WRONG_TYPE;
    if (pub_key->value.octet_string.len != (dh_pub_key_len << 1))
        return WRONG_LENGTH;
    size_t agent_key_len;
    uint8_t *agent_key = get_pub_key_encoded(user, auth, &agent_key_len);

    SnmpErrorStatus res;
    if (agent_key == NULL || agent_key_len != dh_pub_key_len ||
        memcmp(agent_key, pub_key->value.octet_string.octets, dh_pub_key_len)) {
        res = WRONG_VALUE;
    } else {
        res = NO_ERROR;
    }
    free(agent_key);
    return res;
}

/**
 * get_pub_key_encoded - returns DER encoded public key for given user.
 *
 * @user    IN  - user slot
 * @auth    IN  - set to 0 if privacy keypair is requested
 * @pub_key IN  - user provided public key
 * @return 0 on success, -1 on failure.
 */
static int derive_and_apply(SnmpUserSlot user, int auth, uint8_t *pub_key)
{
    uint8_t *secret = NULL;
    size_t secret_len = 0;
    DH *keypair = get_dh_key(user, auth);
    if (keypair == NULL)
        return -1;

    BIGNUM *pub_num = BN_bin2bn(pub_key, dh_pub_key_len, NULL);
    if (pub_num == NULL)
        return -1;

    secret_len = DH_size(keypair);
    if ((secret = calloc(1, secret_len)) == NULL)
        goto err;
    if (DH_compute_key(secret, pub_num, keypair) == -1)
        goto err;

    UserConfiguration *config = get_user_configuration(user);
    syslog(LOG_INFO, "updating %s key for user %s",
        auth ? "authentication" : "privacy",
        (config == NULL || config->name == NULL) ? "unknown" : config->name);

    /* write to configuration */
    if (auth) {
        if (secret_len < USM_HASH_KEY_LEN) {
            syslog(LOG_WARNING, "derived authentication key has size %zu "
                "while minimum of " STRING(USM_HASH_KEY_LEN) " is required", secret_len);
            goto err;
        }

        uint8_t *secret_ptr = secret + (secret_len - USM_HASH_KEY_LEN);
        set_user_auth_key(user, secret_ptr, USM_HASH_KEY_LEN);
    } else {
        if (secret_len < AES_KEY_LEN) {
            syslog(LOG_WARNING, "derived privacy key has size %zu while "
                "minimum of " STRING(AES_KEY_LEN) " is required", secret_len);
            goto err;
        }

        uint8_t *secret_ptr = secret + (secret_len - AES_KEY_LEN);
        set_user_priv_key(user, secret_ptr, AES_KEY_LEN);
    }
    write_configuration();

    /* update runtime */
    update_notification_keyset();
    update_incoming_keyset();

    DH_free(keypair);
    if (auth) {
        user_auth_keys[user-1] = NULL;
    } else {
        user_priv_keys[user-1] = NULL;
    }

    if (secret != NULL) {
        memset(secret, 0, secret_len);
        free(secret);
    }
    BN_free(pub_num);
    return 0;
err:
    free(secret);
    BN_free(pub_num);
    return -1;
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    size_t params_len = 0;
    uint8_t *params = get_params_encoded(&params_len);
    if (params == NULL)
        return GENERAL_ERROR;
    SET_OCTET_STRING_BIND(binding, params, params_len);
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
    UserConfiguration *user = get_user_row(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, user);

    switch (column) {
        case USM_DH_USER_AUTH_KEY_CHANGE:
        case USM_DH_USER_OWN_AUTH_KEY_CHANGE: {
            if (user->user == USER_PUBLIC) {
                SET_OCTET_STRING_BIND(binding, NULL, 0);
            } else {
                size_t pub_key_len;
                uint8_t *pub_key = get_pub_key_encoded(user->user, 1, &pub_key_len);
                if (pub_key == NULL)
                    return GENERAL_ERROR;
                SET_OCTET_STRING_BIND(binding, pub_key, pub_key_len);
            }
            break;
        }

        case USM_DH_USER_PRIV_KEY_CHANGE:
        case USM_DH_USER_OWN_PRIV_KEY_CHANGE: {
            if (user->user == USER_PUBLIC) {
                SET_OCTET_STRING_BIND(binding, NULL, 0);
            } else {
                size_t pub_key_len;
                uint8_t *pub_key = get_pub_key_encoded(user->user, 0, &pub_key_len);
                if (pub_key == NULL)
                    return GENERAL_ERROR;
                SET_OCTET_STRING_BIND(binding, pub_key, pub_key_len);
            }
            break;
        }

        default: {
            return GENERAL_ERROR;
        }
    }

    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);
    INSTANCE_FOUND_OCTET_STRING_ROW2(next_row, SNMP_OID_USM_DH_PUBLIC, id, \
        column, engine_id, engine_id_len, (uint8_t *) user->name, \
        user->name == NULL ? 0 : strlen(user->name));
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *index, size_t index_len,
    SnmpVariableBinding *binding, int dry_run)
{
    UserConfiguration *user = get_user_row(index, index_len, 0);
    if (user == NULL)
        return NO_CREATION;
    if (user->user == USER_PUBLIC)
        return NOT_WRITABLE;

    switch (column) {
        case USM_DH_USER_AUTH_KEY_CHANGE:
        case USM_DH_USER_OWN_AUTH_KEY_CHANGE: {
            if (dry_run) {
                return validate_pub_key(user->user, 1, binding);
            } else {
                if (derive_and_apply(user->user, 1,
                    binding->value.octet_string.octets + dh_pub_key_len))
                    return GENERAL_ERROR;
            }
            break;
        }

        case USM_DH_USER_PRIV_KEY_CHANGE:
        case USM_DH_USER_OWN_PRIV_KEY_CHANGE: {
            if (dry_run) {
                return validate_pub_key(user->user, 0, binding);
            } else {
                if (derive_and_apply(user->user, 0,
                    binding->value.octet_string.octets + dh_pub_key_len))
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

MibModule *init_usm_dh_module(void)
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
