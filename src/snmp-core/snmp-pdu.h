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

#ifndef SRC_SNMP_CORE_SNMP_PDU_H_
#define SRC_SNMP_CORE_SNMP_PDU_H_

#include "snmp-core/snmp-types.h"

#define SNMP_VERSION 3

#define MAX_CONTEXT_ENGINE_ID   0x40
#define MAX_CONTEXT_ENGINE_NAME 0x40
#define MAX_SNMP_VAR_BINDINGS   0x40

#define MAX_ENGINE_ID_LENGTH          0x40
#define MAX_USER_NAME_LENGTH          0x40
#define MAX_AUTHENTICATION_PARAMETERS 0x40
#define MAX_PRIVACY_PARAMETERS        0x40

#define PARSE_SUCCESS          0
#define PARSE_ERROR           -1
#define PARSE_ERROR_VERSION   -2
#define PARSE_ERROR_SEC_MODEL -3

#define NEW_VAR_BINDING(x,y) \
	SnmpVariableBinding *x = add_variable_binding(y); \
	if (x == NULL) { \
        syslog(LOG_WARNING, "PDU building error: no variable binding slots left"); \
        return -1; \
	}

/** SNMP PDU types */
typedef enum {
    GET = 0xA0,
    GET_NEXT = 0xA1,
    RESPONSE = 0xA2,
    SET = 0xA3,
    GET_BULK = 0xA5,
    INFORM = 0xA6,
    TRAP = 0xA7,
    REPORT = 0xA8
} SnmpPduType;

/** SNMP error status */
typedef enum {
    NO_ERROR = 0,
    TOO_BIG = 1,

    /* for proxy compatibility */
    NO_SUCH_NAME = 2,
    BAD_VALUE = 3,
    READ_ONLY = 4,

    GENERAL_ERROR = 5,
    NO_ACCESS = 6,
    WRONG_TYPE = 7,
    WRONG_LENGTH = 8,
    WRONG_ENCODING = 9,
    WRONG_VALUE = 10,
    NO_CREATION = 11,
    INCONSISTENT_VALUE = 12,
    RESOURCE_UNAVAILABLE = 13,
    COMMIT_FAILED = 14,
    UNDO_FAILED = 15,
    AUTHORIZATION_ERROR = 16,
    NOT_WRITABLE = 17,
    INCONSISTENT_NAME = 18
} SnmpErrorStatus;

/** USM security parameter block, included in SNMP PDU header */
typedef struct {

    /* authoritative engine ID */
    uint8_t authoritative_engine_id[MAX_ENGINE_ID_LENGTH];
    size_t authoritative_engine_id_len;

    /* authoritative engine boot counter and time */
    uint32_t authoritative_engine_boots;
    uint32_t authoritative_engine_time;

    /* securityName */
    char user_name[MAX_USER_NAME_LENGTH];

    /* authentication parameters (digest) */
    uint8_t authentication_parameters[MAX_AUTHENTICATION_PARAMETERS];
    size_t authentication_parameters_len;

    /* privacy parameters (salt) */
    uint8_t privacy_parameters[MAX_PRIVACY_PARAMETERS];
    size_t privacy_parameters_len;

} SnmpUSMSecurityParameters;

/* Scoped PDU */
typedef struct {

    /* context engine identifier */
    uint8_t context_engine_id[MAX_CONTEXT_ENGINE_ID];
    size_t context_engine_id_len;

    /* context engine name */
    uint8_t context_engine_name[MAX_CONTEXT_ENGINE_NAME];
    size_t context_engine_name_len;

    /* request identifier */
    uint32_t request_id;

    /* request type */
    SnmpPduType type;

    /* for non-bulk requests only */
    SnmpErrorStatus error_status;
    uint32_t error_index;

    /* for bulk requests only */
    uint32_t non_repeaters;
    uint32_t max_repetitions;

    /* variable bindings */
    SnmpVariableBinding bindings[MAX_SNMP_VAR_BINDINGS];
    size_t num_of_bindings;

} SnmpScopedPDU;

/** SNMP message */
typedef struct {

    /* Message identifier */
    uint32_t message_id;

    /* Maximum message size (including header) */
    uint32_t max_size;

    /* Scoped PDU is encrypted */
    uint8_t is_encrypted;

    /* Scoped PDU is authenticated */
    uint8_t is_authenticated;

    /* Message requires response */
    uint8_t requires_response;

    /* Security parameter block */
    SnmpUSMSecurityParameters security_parameters;

    /* Scoped PDU */
    union {
        struct {
            uint8_t *data;
            size_t len;
        } encrypted_pdu;
        SnmpScopedPDU *decrypted_pdu;
    } scoped_pdu;
} SnmpPDU;

/**
 * @internal
 * decode_snmp_pdu - Extracts an SNMP PDU from a given BER encoded TLV.
 *
 * @param src IN - TLV containing SNMP PDU.
 * @param pdu OUT - destination pdu struct
 *
 * @return 0 on success, negative number on error (see PARSE_* defines)
 * @note scoped PDU is not decrypted or parsed by this function.
 */
int decode_snmp_pdu(const asn1raw_t *src, SnmpPDU *pdu);

/**
 * @internal
 * encode_snmp_pdu - Encodes an SNMP pdu into a BER TLV.
 *
 * @param pdu IN - PDU to be encoded.
 * @param dst OUT - destination output.
 * @param dummy_scoped_pdu IN - if non-zero, skip the scoped PDU
 * 		and assume scoped PDU size as given.
 *
 * @return 0 on success, -1 on error.
 * @note scoped PDU is expected already encrypted
 */
int encode_snmp_pdu(const SnmpPDU *pdu, buf_t *dst, const int dummy_scoped_pdu);

/**
 * @internal
 * decode_usm_security_parameters - Extracts USM security parameters
 * from given BER encoded TLV.
 *
 * @param src IN - TLV containing USM security parameters.
 * @param params OUT - destination parameter block
 *
 * @return 0 on success, -1 on parse error.
 */
int decode_usm_security_parameters(const asn1raw_t *src, SnmpUSMSecurityParameters *params);

/**
 * @internal
 * encode_usm_security_parameters - Encodes the USM security parameters to a BER TLV.
 *
 * @param params IN - USM parameter block to be encoded.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 on encoding error.
 */
int encode_usm_security_parameters(const SnmpUSMSecurityParameters *params, buf_t *dst);

/**
 * @internal
 * decode_snmp_scoped_pdu - Extracts a scoped SNMP PDU from a
 * given BER encoded TLV.
 *
 * @param src IN - TLV containing scoped PDU.
 * @param pdu OUT - destination scoped pdu struct
 *
 * @return 0 on success, -1 on parse error
 */
int decode_snmp_scoped_pdu(const asn1raw_t *src, SnmpScopedPDU *pdu);

/**
 * @internal
 * encode_snmp_scoped_pdu - Encodes a scoped SNMP pdu into a BER TLV.
 *
 * @param pdu IN - Scoped PDU to be encoded.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 on encoding error.
 */
int encode_snmp_scoped_pdu(const SnmpScopedPDU *pdu, buf_t *dst);

/**
 * @internal
 * add_variable_binding - Adds a new variable binding to a scoped PDU.
 *
 * @param pdu IN/OUT - Scoped PDU.
 *
 * @return reference to the new variable binding, NULL on error.
 */
SnmpVariableBinding *add_variable_binding(SnmpScopedPDU *pdu);

#ifdef DEBUG
/**
 * @internal
 * dump_pdu - Dumps the content of the SNMP PDU to syslog.
 *
 * @param pdu IN - PDU to be logged.
 * @param scoped_pdu_decrypted IN - indicates if scoped PDU is decrypted and parsed.
 */
void dump_snmp_pdu(const SnmpPDU *pdu, const int scoped_pdu_decrypted);

/**
 * @internal
 * dump_pdu - Dumps the content of the scoped PDU to syslog.
 *
 * @param pdu IN - PDU to be logged.
 */
void dump_snmp_scoped_pdu(const SnmpScopedPDU *pdu);
#endif

#endif /* SRC_SNMP_CORE_SNMP_PDU_H_ */
