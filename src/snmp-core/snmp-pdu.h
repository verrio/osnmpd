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

#define GET_SCOPED_PDU(pdu) (&(pdu).scoped_pdu.decrypted)

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

    /* The agent reports that no errors occurred during transmission. */
    NO_ERROR = 0,

    /* The agent could not place the results of the requested SNMP
     * operation in a single SNMP message. */
    TOO_BIG = 1,

    /* for proxy compatibility */

    /* The requested SNMP operation identified an unknown variable. */
    NO_SUCH_NAME = 2,

    /* The requested SNMP operation tried to change a variable
     * but it specified either a syntax or value error. */
    BAD_VALUE = 3,

    /* The requested SNMP operation tried to change a variable
     * that was not allowed to change, according to the community
     * profile of the variable. */
    READ_ONLY = 4,

    /* An error other than one of those listed here occurred
     * during the requested SNMP operation. */
    GENERAL_ERROR = 5,

    /* The specified SNMP variable is not accessible. */
    NO_ACCESS = 6,

    /* The value specifies a type that is inconsistent
     * with the type required for the variable. */
    WRONG_TYPE = 7,

    /* The value specifies a length that is inconsistent
     * with the length required for the variable. */
    WRONG_LENGTH = 8,

    /* The value contains an ASN.1 encoding that is inconsistent
     * with the ASN.1 tag of the field. */
    WRONG_ENCODING = 9,

    /* The value cannot be assigned to the variable. */
    WRONG_VALUE = 10,

    /* The variable does not exist, and the agent cannot create it. */
    NO_CREATION = 11,

    /* The value is inconsistent with values of other managed objects. */
    INCONSISTENT_VALUE = 12,

    /* Assigning the value to the variable requires allocation
     * of resources that are currently unavailable. */
    RESOURCE_UNAVAILABLE = 13,

    /* No validation errors occurred, but no variables were updated. */
    COMMIT_FAILED = 14,

    /* No validation errors occurred. Some variables were updated
     * because it was not possible to undo their assignment. */
    UNDO_FAILED = 15,

    /* An authorization error occurred. */
    AUTHORIZATION_ERROR = 16,

    /* The variable exists but the agent cannot modify it. */
    NOT_WRITABLE = 17,

    /* The variable does not exist; the agent cannot create it
     * because the named object instance is inconsistent with
     * the values of other managed objects. */
    INCONSISTENT_NAME = 18

} SnmpErrorStatus;

/** USM security parameter block, included in SNMP PDU header */
typedef struct {

    /* authoritative engine ID */
    uint8_t auth_engine_id[MAX_ENGINE_ID_LENGTH];
    size_t auth_engine_id_len;

    /* authoritative engine boot counter and time */
    uint32_t auth_engine_boots;
    uint32_t auth_engine_time;

    /* securityName */
    char user_name[MAX_USER_NAME_LENGTH];

    /* authentication parameters (digest) */
    uint8_t auth_param[MAX_AUTHENTICATION_PARAMETERS];
    size_t auth_param_len;
    uint8_t *auth_param_offset;

    /* privacy parameters (salt) */
    uint8_t priv_param[MAX_PRIVACY_PARAMETERS];
    size_t priv_param_len;

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
    SnmpUSMSecurityParameters security_params;

    /* Scoped PDU */
    union {
        struct {
            uint8_t *data;
            size_t len;
        } encrypted;
        SnmpScopedPDU decrypted;
    } scoped_pdu;

} SnmpPDU;

/**
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
int encode_snmp_pdu(SnmpPDU *pdu, buf_t *dst, const int dummy_scoped_pdu);

/**
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
 * encode_usm_security_parameters - Encodes the USM security parameters to a BER TLV.
 *
 * @param params IN/OUT - USM parameter block to be encoded.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 on encoding error.
 */
int encode_usm_security_parameters(SnmpUSMSecurityParameters *params, buf_t *dst);

/**
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
 * encode_snmp_scoped_pdu - Encodes a scoped SNMP pdu into a BER TLV.
 *
 * @param pdu IN - Scoped PDU to be encoded.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 on encoding error.
 */
int encode_snmp_scoped_pdu(const SnmpScopedPDU *pdu, buf_t *dst);

/**
 * add_variable_binding - Adds a new variable binding to a scoped PDU.
 *
 * @param pdu IN/OUT - Scoped PDU.
 *
 * @return reference to the new variable binding, NULL on error.
 */
__attribute__((visibility("default")))
SnmpVariableBinding *add_variable_binding(SnmpScopedPDU *pdu);

#ifdef DEBUG
/**
 * dump_pdu - Dumps the content of the SNMP PDU to syslog.
 *
 * @param pdu IN - PDU to be logged.
 * @param scoped_pdu_decrypted IN - indicates if scoped PDU is decrypted and parsed.
 */
void dump_snmp_pdu(const SnmpPDU *pdu, const int scoped_pdu_decrypted);

/**
 * dump_pdu - Dumps the content of the scoped PDU to syslog.
 *
 * @param pdu IN - PDU to be logged.
 */
void dump_snmp_scoped_pdu(const SnmpScopedPDU *pdu);
#endif

#endif /* SRC_SNMP_CORE_SNMP_PDU_H_ */
