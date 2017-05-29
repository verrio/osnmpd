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

#include "snmp-crypto.h"

#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "snmp-core/tinyber.h"
#include "snmp-core/utils.h"

#ifdef WITH_SMARTCARD_SUPPORT
#define ENGINE_ID "smartcard"
static ENGINE *smartcard_engine = NULL;
#endif

#define MAX_HEADER_LEN 512

int init_crypto(void)
{
    OPENSSL_config(NULL);
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

#ifdef WITH_SMARTCARD_SUPPORT
    ENGINE_load_builtin_engines();
    smartcard_engine = ENGINE_by_id(ENGINE_ID);
    if (smartcard_engine == NULL) {
        syslog(LOG_ERR, "failed to load smartcard engine.");
        return -1;
    }

    if (ENGINE_init(smartcard_engine) != 1) {
        syslog(LOG_ERR, "failed to initialize smartcard engine.");
        return -1;
    }
#endif

    return 0;
}

int finish_crypto(void)
{
    CONF_modules_free();
    OBJ_cleanup();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

#ifdef WITH_SMARTCARD_SUPPORT
    if (smartcard_engine != NULL) {
        ENGINE_finish(smartcard_engine);
        ENGINE_free(smartcard_engine);
    }
    ENGINE_cleanup();
#endif

    return 0;
}

#ifdef WITH_SMARTCARD_SUPPORT
ENGINE *get_smartcard_engine(void)
{
    return smartcard_engine;
}
#endif

static int generate_tag(uint8_t *pdu, size_t pdu_len,
        uint8_t *auth_tag, const SnmpUSMContext *context)
{
    memset(auth_tag, 0, USM_HMAC_TRUNC_LEN);

    int res = -1;
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    if (!HMAC_Init_ex(&ctx, context->auth_key,
        context->auth_key_len, USM_HMAC_ALGO(), NULL))
        goto err;
    if (!HMAC_Update(&ctx, pdu, pdu_len))
        goto err;
    uint8_t tag_buf[EVP_MAX_MD_SIZE];
    if (!HMAC_Final(&ctx, tag_buf, NULL))
        goto err;
    memcpy(auth_tag, tag_buf, USM_HMAC_TRUNC_LEN);
    res = 0;
err:
    HMAC_CTX_cleanup(&ctx);
    return res;
}

static void generate_iv(uint8_t *iv, uint32_t engine_time, uint32_t engine_boots,
        uint8_t *local_iv)
{
    iv[0] = engine_boots >> 24;
    iv[1] = engine_boots >> 16;
    iv[2] = engine_boots >> 8;
    iv[3] = engine_boots;
    iv[4] = engine_time >> 24;
    iv[5] = engine_time >> 16;
    iv[6] = engine_time >> 8;
    iv[7] = engine_time;
    memcpy(&iv[8], local_iv, AES_IV_LEN >> 1);
}

static int check_replay_counter(const SnmpPDU *pdu, SnmpUSMContext *context)
{
    if (context->get_engine_boots() != pdu->security_params.auth_engine_boots)
        return -1;

    uint32_t engine_time = context->get_engine_time();
    if (engine_time < context->last_incoming_time)
        context->last_incoming_time = 0;

    if (abs(engine_time - pdu->security_params.auth_engine_time) > 250)
        /* RFC requires 150 sec max, but some clients seem
         * to go out-of-sync too fast that way */
        return -1;
    if (pdu->security_params.auth_engine_time < context->last_incoming_time)
        return -1;
    if (pdu->security_params.auth_engine_time == context->last_incoming_time &&
        pdu->message_id == context->last_incoming_msg_id &&
        !memcmp(context->last_incoming_iv, pdu->security_params.priv_param,
            min(pdu->security_params.priv_param_len,
                sizeof(context->last_incoming_iv)))) {
        return -1;
    }

    return 0;
}

static int decrypt_scoped_pdu(SnmpPDU *pdu, const SnmpUSMContext *context)
{
    buf_t buf;
    asn1raw_t raw_tlv;

    if (pdu->is_encrypted) {
        if (pdu->security_params.priv_param_len != (AES_IV_LEN >> 1))
            return -1;

        init_ibuf(&buf, pdu->scoped_pdu.encrypted.data,
            pdu->scoped_pdu.encrypted.len);
        if (decode_TLV(&raw_tlv, &buf))
            return -1;
        if (raw_tlv.type != TAG_OCTETSTRING)
            return -1;

        uint8_t iv[AES_IV_LEN];
        generate_iv(iv, pdu->security_params.auth_engine_time,
                pdu->security_params.auth_engine_boots,
                pdu->security_params.priv_param);

        AES_KEY key;
        if (AES_set_encrypt_key(context->priv_key, AES_KEY_LEN << 3, &key))
            return -1;

        int offset = 0;
        AES_cfb128_encrypt(raw_tlv.value, pdu->scoped_pdu.encrypted.data,
                raw_tlv.length, &key, iv, &offset, AES_DECRYPT);
        pdu->scoped_pdu.encrypted.len = raw_tlv.length;
    }

    init_ibuf(&buf, pdu->scoped_pdu.encrypted.data, pdu->scoped_pdu.encrypted.len);
    if (decode_TLV(&raw_tlv, &buf))
        return -1;
    if (decode_snmp_scoped_pdu(&raw_tlv, &pdu->scoped_pdu.decrypted))
        return -1;
    return 0;
}

static int encrypt_scoped_pdu(SnmpPDU *pdu, buf_t *dst, const SnmpUSMContext *context)
{
    pdu->security_params.auth_engine_time = context->get_engine_time();
    pdu->security_params.auth_engine_boots = context->get_engine_boots();
    pdu->security_params.priv_param_len = AES_IV_LEN >> 1;
    if (RAND_bytes(pdu->security_params.priv_param, AES_IV_LEN >> 1) != 1) {
        syslog(LOG_ERR, "failed to generate iv nonce : %s",
                ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    uint8_t iv[AES_IV_LEN];
    generate_iv(iv, pdu->security_params.auth_engine_time,
            pdu->security_params.auth_engine_boots,
            pdu->security_params.priv_param);

    AES_KEY key;
    if (AES_set_encrypt_key(context->priv_key, AES_KEY_LEN << 3, &key))
        return -1;
    int offset = 0;
    AES_cfb128_encrypt(&dst->buffer[dst->pos], &dst->buffer[dst->pos],
            dst->size - dst->pos, &key, iv, &offset, AES_ENCRYPT);

    return 0;
}

/**
 * Derive key from password (RFC 2274)
 */
static int derive_key(const char *password, uint8_t *dst, size_t *dst_len)
{
    if (strlen(password) < 1)
        return -1;

    USM_HASH_CTX context;
    if (!USM_HASH_INIT(&context)) {
        return -1;
    }

    int index = 0;
    int count = 0;
    size_t passwd_len = strlen(password);
    uint8_t buf[USM_HMAC_BLOCK_SIZE];

    /* process till 1Mb exceeded */
    while (count < 1048576) {
        /* expand password to fill the buffer */
        for (int i = 0; i < USM_HMAC_BLOCK_SIZE; i++)
            buf[i] = password[index++ % passwd_len];
        if (!USM_HASH_UPDATE(&context, buf, USM_HMAC_BLOCK_SIZE))
            return -1;
        count += USM_HMAC_BLOCK_SIZE;
    }

    if (!USM_HASH_FINAL(dst, &context))
        return -1;
    *dst_len = USM_HASH_LEN;

    char hex_dump[HEX_LEN(USM_HASH_LEN)];
    if (to_hex(dst, USM_HASH_LEN, hex_dump, sizeof(hex_dump)) > 0)
        syslog(LOG_DEBUG, "derived master key %s", hex_dump);
    return 0;
}

/**
 * Diversify key using engine ID (RFC 3414)
 */
static int diversify_key(const uint8_t *src, const size_t src_len, uint8_t *dst,
        const uint8_t *engine_id, const size_t engine_id_len)
{
	USM_HASH_CTX c;
    if (!USM_HASH_INIT(&c))
        return -1;
    if (!USM_HASH_UPDATE(&c, src, src_len))
        return -1;
    if (!USM_HASH_UPDATE(&c, engine_id, engine_id_len))
        return -1;
    if (!USM_HASH_UPDATE(&c, src, src_len))
        return -1;
    if (!USM_HASH_FINAL(dst, &c))
        return -1;

    char hex_dump[HEX_LEN(USM_HASH_KEY_LEN)];
    if (to_hex(dst, USM_HASH_KEY_LEN, hex_dump, sizeof(hex_dump)) > 0)
        syslog(LOG_DEBUG, "derived diversified key %s", hex_dump);

    return 0;
}

int derive_usm_master_keys(const SnmpUSMSecret *priv_secret,
        const SnmpUSMSecret *auth_secret, SnmpUSMContext *context)
{
    if (priv_secret != NULL && priv_secret->secret.key != NULL) {
        if (priv_secret->is_key) {
            context->priv_key_len = min(AES_KEY_LEN, priv_secret->secret_len);
            memcpy(context->priv_key, priv_secret->secret.key, context->priv_key_len);
            context->priv_diversified = 1;
        } else {
            if (derive_key(priv_secret->secret.password,
                    context->priv_key, &context->priv_key_len))
                return -1;
            context->priv_diversified = 0;
        }
    } else {
        context->priv_key_len = 0;
        context->priv_diversified = 0;
    }

    if (auth_secret != NULL && auth_secret->secret.key != NULL) {
        if (auth_secret->is_key) {
            context->auth_key_len = min(USM_HASH_KEY_LEN, auth_secret->secret_len);
            memcpy(context->auth_key, auth_secret->secret.key, context->auth_key_len);
            context->auth_diversified = 1;
        } else {
            if (derive_key(auth_secret->secret.password,
                    context->auth_key, &context->auth_key_len))
                return -1;
            context->auth_diversified = 0;
        }
    } else {
        context->auth_key_len = 0;
        context->auth_diversified = 0;
    }

    return 0;
}

int derive_usm_diversified_keys(const uint8_t *engine_id,
        const size_t engine_id_len, SnmpUSMContext *context)
{
    if (!context->auth_diversified &&
        !context->priv_diversified && engine_id == NULL)
        return -1;
    if (!context->auth_diversified &&
        diversify_key(context->auth_key, context->auth_key_len,
        context->auth_key, engine_id, engine_id_len))
        return -1;
    if (!context->priv_diversified &&
        diversify_key(context->priv_key, context->priv_key_len,
        context->priv_key, engine_id, engine_id_len))
        return -1;
    context->priv_key_len = AES_KEY_LEN;
    context->auth_diversified = context->priv_diversified = 1;

    return 0;
}

int process_incoming_pdu(uint8_t *src, size_t src_len, SnmpPDU *pdu,
        SnmpUSMContext *context, int time_sync)
{
    /* validate PDU header */
    if (context->level > NO_AUTH_NO_PRIV && !pdu->is_authenticated)
        return PROCESSING_SECURITY_LEVEL_INVALID;
    if (context->level < AUTH_NO_PRIV && pdu->is_authenticated)
        return PROCESSING_SECURITY_LEVEL_INVALID;
    if (!time_sync) {
        if (context->level > AUTH_NO_PRIV && !pdu->is_encrypted)
            return PROCESSING_SECURITY_LEVEL_INVALID;
        if (context->level < AUTH_PRIV && pdu->is_encrypted)
            return PROCESSING_SECURITY_LEVEL_INVALID;
    }

    if (context->level > NO_AUTH_NO_PRIV) {
        /* validate timestamp */
        if (!time_sync && check_replay_counter(pdu, context))
            return PROCESSING_SECURITY_TIME_INVALID;

        /* validate tag */
        if (pdu->security_params.auth_param_len != USM_HMAC_TRUNC_LEN)
            return PROCESSING_SECURITY_AUTH_FAILED;
        if (generate_tag(src, src_len,
            pdu->security_params.auth_param_offset, context)) {
            return PROCESSING_SECURITY_AUTH_FAILED;
        } else {
            uint32_t res = 0;
            for (int i = 0; i < USM_HMAC_TRUNC_LEN; i++) {
                res |= pdu->security_params.auth_param[i] ^
                       pdu->security_params.auth_param_offset[i];
            }
            if ((1 & ((res - 1) >> 8)) - 1) {
                return PROCESSING_SECURITY_AUTH_FAILED;
            }
        }
    }

    /* decrypt scoped PDU */
    if (decrypt_scoped_pdu(pdu, context))
        return PROCESSING_SECURITY_ENC_FAILED;

    /* cache authentication values for replay protection */
    context->last_incoming_msg_id = pdu->message_id;
    context->last_incoming_time = pdu->security_params.auth_engine_time;
    memcpy(context->last_incoming_iv, pdu->security_params.priv_param,
        min(pdu->security_params.priv_param_len, sizeof(context->last_incoming_iv)));

    return PROCESSING_NO_ERROR;
}

int process_outgoing_pdu(SnmpPDU *pdu, buf_t *dst, const SnmpUSMContext *context)
{
    unsigned int mark = dst->pos;

    if (encode_snmp_scoped_pdu(&pdu->scoped_pdu.decrypted, dst))
        return -1;

    /* encrypt scoped PDU */
    if (pdu->is_encrypted) {
        if (encrypt_scoped_pdu(pdu, dst, context))
            return -1;
        if (encode_TLV(dst, mark, TAG_OCTETSTRING, FLAG_UNIVERSAL))
            return -1;
    }

    /* put dummy tag */
    if (pdu->is_authenticated) {
        memset(pdu->security_params.auth_param, 0, USM_HMAC_TRUNC_LEN);
        pdu->security_params.auth_param_len = USM_HMAC_TRUNC_LEN;
    } else {
        pdu->security_params.auth_param_len = 0;
    }

    if (encode_snmp_pdu(pdu, dst, mark - dst->pos))
        return -1;

    /* apply tag */
    if (pdu->is_authenticated && generate_tag(&dst->buffer[dst->pos],
        mark - dst->pos, pdu->security_params.auth_param_offset, context))
        return -1;

    return 0;
}
