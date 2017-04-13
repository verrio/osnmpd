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

#ifndef SRC_SNMP_CORE_SNMP_CRYPTO_H_
#define SRC_SNMP_CORE_SNMP_CRYPTO_H_

#include "config.h"
#include <openssl/sha.h>
#ifdef WITH_SMARTCARD_SUPPORT
#include <openssl/engine.h>
#endif

#include "snmp-core/snmp-pdu.h"

#define SNMP_SECURITY_MODEL           0x03

#define AES_KEY_LEN                   0x10
#define AES_IV_LEN                    0x10
#define HMAC_BLOCK_SIZE               0x40
#define HMAC_KEY_LEN                  SHA_DIGEST_LENGTH
#define HMAC_TAG_LEN                  0x0C

#define PROCESSING_NO_ERROR                  0
#define PROCESSING_PARSE_ERROR              -1
#define PROCESSING_SECURITY_LEVEL_INVALID   -2
#define PROCESSING_SECURITY_TIME_INVALID    -3
#define PROCESSING_SECURITY_AUTH_FAILED     -4
#define PROCESSING_SECURITY_ENC_FAILED	    -5

/* SNMPv2c/SNMPv3 security models */
typedef enum {
    COMMUNITY = 0,
    USM = 1,
    TSM = 2,
    SSH = 3,
    NUMBER_OF_SEC_MODELS = 4
} SnmpSecurityModel;

/* USM security levels */
typedef enum {
    NO_AUTH_NO_PRIV = 0,
    AUTH_NO_PRIV = 1,
    AUTH_PRIV = 2,
    NUMBER_OF_SEC_LEVELS = 3
} SnmpSecurityLevel;

/** USM security context */
typedef struct {

    /* USM level */
    SnmpSecurityLevel level;

    /* USM securityName */
    char user_name[MAX_USER_NAME_LENGTH];
    size_t user_name_len;

    /* USM keys */
    uint8_t auth_key[HMAC_KEY_LEN];
    size_t auth_key_len;
    uint8_t priv_key[HMAC_KEY_LEN];
    size_t priv_key_len;

    /* engine parameters */
    uint32_t (*get_engine_boots)(void);
    uint32_t (*get_engine_time)(void);

    /* anti-replay */
    uint32_t last_incoming_time;
    uint32_t last_incoming_msg;

} SnmpUSMContext;

/**
 * @internal
 * init_crypto - initialize the crypto libraries.
 *
 * @return 0 on success or -1 on any error
 */
int init_crypto(void);

/**
 * @internal
 * finish_crypto - finalize the crypto libraries.
 *
 * @return 0 on success or -1 on any error
 */
int finish_crypto(void);

#ifdef WITH_SMARTCARD_SUPPORT
/**
 * @internal
 * get_smartcard_engine - returns a handle to the smartcard engine
 *
 * @return smartcard engine, or NULL if not available.
 */
ENGINE *get_smartcard_engine(void);
#endif

/**
 * @internal
 * derive_usm_master_keys - Derive the master keyset for a given pair of passwords.
 *
 * @param priv_password IN - privacy password (null terminated)
 * @param priv_password IN - authentication password (null terminated)
 * @param context OUT - USM context.
 *
 * @return 0 on success, -1 on error.
 */
int derive_usm_master_keys(const char *priv_password,
        const char *auth_password, SnmpUSMContext *context);

/**
 * @internal
 * derive_usm_diversified_keys - Derive diversified (localized) keys
 * for the given USM context and engine ID.
 *
 * @param engine_id IN - Engine ID
 * @param engine_id_len IN - Length of the engine ID
 * @param context IN/OUT - USM context with master keys initialized.
 *
 * @return 0 on success, -1 on error.
 */
int derive_usm_diversified_keys(const uint8_t *engine_id,
        const size_t engine_id_len, SnmpUSMContext *context);

/**
 * @internal
 * process_incoming_pdu - authenticates and decrypts an incoming PDU.
 *
 * @param pdu IN - Incoming PDU without parsed scoped PDU.
 * @param scoped_pdu OUT - destination buffer for decrypted scoped PDU.
 * @param context IN - USM context.
 * @param time_sync IN - if non-zero, PDU is assumed to be time sync request.
 *
 * @return 0 on success, negative number on processing error.
 */
int process_incoming_pdu(SnmpPDU *pdu, SnmpScopedPDU *scoped_pdu,
        SnmpUSMContext *context, int time_sync);

/**
 * @internal
 * process_outgoing_pdu - authenticates, encrypts and marshalls an outgoing PDU.
 *
 * @param pdu IN - PDU to be sent out.
 * @param dst OUT - destination buffer for the resulting BER encoded datastream.
 * @param context IN - USM context.
 *
 * @return 0 on success, -1 on error.
 */
int process_outgoing_pdu(SnmpPDU *pdu, buf_t *dst, const SnmpUSMContext *context);

#endif /* SRC_SNMP_CORE_SNMP_CRYPTO_H_ */
