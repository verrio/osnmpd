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

#include "snmp-core/snmp-core.h"
#include "snmp-core/snmp-crypto.h"
#include "snmp-core/snmp-pdu.h"
#include "snmp-core/snmp-types.h"
#include "snmp-core/tinyber.h"
#include "snmp-core/utils.h"

static SnmpErrorStatus get_error_status(asn1int_t status)
{
    switch (status) {
        case NO_ERROR:
        case TOO_BIG:
        case NO_SUCH_NAME:
        case BAD_VALUE:
        case READ_ONLY:
        case GENERAL_ERROR:
        case NO_ACCESS:
        case WRONG_TYPE:
        case WRONG_LENGTH:
        case WRONG_ENCODING:
        case WRONG_VALUE:
        case NO_CREATION:
        case INCONSISTENT_VALUE:
        case RESOURCE_UNAVAILABLE:
        case COMMIT_FAILED:
        case UNDO_FAILED:
        case AUTHORIZATION_ERROR:
        case NOT_WRITABLE:
        case INCONSISTENT_NAME: {
            return (SnmpErrorStatus) status;
        }

        default: {
            return -1;
        }
    }
}

static SnmpPduType get_pdu_type(asn1int_t id)
{
    switch (id) {
        case GET:
        case GET_NEXT:
        case RESPONSE:
        case SET:
        case GET_BULK:
        case INFORM:
        case TRAP:
        case REPORT: {
            return (SnmpPduType) id;
        }

        default: {
            return -1;
        }
    }
}

int decode_snmp_pdu(const asn1raw_t *src, SnmpPDU *pdu)
{
    if (src->type != TAG_SEQUENCE) {
        return -1;
    }

    buf_t buf;
    asn1raw_t raw_tlv;
    init_ibuf(&buf, src->value, src->length);

    /* check version */
    if (decode_TLV(&raw_tlv, &buf)) {
        return PARSE_ERROR;
    } else if (raw_tlv.type != TAG_INTEGER) {
        return PARSE_ERROR;
    } else if (decode_INTEGER(&raw_tlv) != SNMP_VERSION) {
        return PARSE_ERROR_VERSION;
    }

    if (decode_TLV(&raw_tlv, &buf)) {
        return PARSE_ERROR;
    } else if (raw_tlv.type != TAG_SEQUENCE) {
        return PARSE_ERROR;
    }

    buf_t global_data;
    init_ibuf(&global_data, raw_tlv.value, raw_tlv.length);

    /* message ID */
    if (decode_TLV(&raw_tlv, &global_data)) {
        return PARSE_ERROR;
    } else if (raw_tlv.type != TAG_INTEGER) {
        return PARSE_ERROR;
    }
    pdu->message_id = decode_INTEGER(&raw_tlv);

    /* max message size */
    if (decode_TLV(&raw_tlv, &global_data)) {
        return PARSE_ERROR;
    } else if (raw_tlv.type != TAG_INTEGER) {
        return PARSE_ERROR;
    }
    pdu->max_size = decode_INTEGER(&raw_tlv);

    /* message flags */
    if (decode_TLV(&raw_tlv, &global_data)) {
        return PARSE_ERROR;
    } else if (raw_tlv.type != TAG_OCTETSTRING) {
        return PARSE_ERROR;
    } else if (raw_tlv.length != 1) {
        return PARSE_ERROR;
    }
    pdu->requires_response = (raw_tlv.value[0] & 0x04) != 0x00;
    pdu->is_encrypted = (raw_tlv.value[0] & 0x02) != 0x00;
    pdu->is_authenticated = (raw_tlv.value[0] & 0x01) != 0x00;
    if (decode_TLV(&raw_tlv, &global_data)) {
        return PARSE_ERROR;
    } else if (raw_tlv.type != TAG_INTEGER) {
        return PARSE_ERROR;
    } else if (decode_INTEGER(&raw_tlv) != SNMP_SECURITY_MODEL) {
        return PARSE_ERROR_SEC_MODEL;
    }

    /* security parameters */
    if (decode_TLV(&raw_tlv, &buf)) {
        return PARSE_ERROR;
    } else if (decode_usm_security_parameters(&raw_tlv,
            &pdu->security_parameters)) {
        return PARSE_ERROR;
    }

    /* scoped PDU */
    pdu->scoped_pdu.encrypted_pdu.data = &buf.buffer[buf.pos];
    pdu->scoped_pdu.encrypted_pdu.len = buf.size - buf.pos;
    if (decode_TLV(&raw_tlv, &buf)) {
        return PARSE_ERROR;
    } else if (buf.pos != buf.size) {
        return PARSE_ERROR;
    }

    return PARSE_SUCCESS;
}

int encode_snmp_pdu(const SnmpPDU *pdu, buf_t *dst, const int dummy_scoped_pdu)
{
    unsigned int mark = dst->pos;

    /* scoped PDU */
    if (dummy_scoped_pdu > 0) {
        mark = dst->pos + dummy_scoped_pdu;
    } else {
        mark = dst->pos;
        dst->pos -= pdu->scoped_pdu.encrypted_pdu.len;
        if (dst->pos < 0) {
            return -1;
        }
        memcpy(&dst->buffer[dst->pos], pdu->scoped_pdu.encrypted_pdu.data,
                pdu->scoped_pdu.encrypted_pdu.len);
    }

    /* security parameters */
    if (encode_usm_security_parameters(&pdu->security_parameters, dst)) {
        return -1;
    }

    /* global message data */
    unsigned global_mark = dst->pos;
    asn1int_t security_model = SNMP_SECURITY_MODEL;
    uint8_t flags = ((pdu->requires_response != 0) << 2)
            | ((pdu->is_encrypted != 0) << 1) | (pdu->is_authenticated != 0);
    asn1int_t max_size = pdu->max_size;
    asn1int_t msg_id = pdu->message_id;
    if (encode_INTEGER(dst, &security_model, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    } else if (encode_OCTET_STRING(dst, &flags, 1)) {
        return -1;
    } else if (encode_INTEGER(dst, &max_size, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    } else if (encode_INTEGER(dst, &msg_id, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    } else if (encode_TLV(dst, global_mark, TAG_SEQUENCE, FLAG_STRUCTURED)) {
        return -1;
    }

    /* message version */
    asn1int_t version = SNMP_VERSION;
    if (encode_INTEGER(dst, &version, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    }

    if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED)) {
        return -1;
    }

    return 0;
}

int decode_usm_security_parameters(const asn1raw_t *src, SnmpUSMSecurityParameters *params)
{
    if (src->type != TAG_OCTETSTRING) {
        return -1;
    }

    buf_t buf;
    asn1raw_t raw_val;
    init_ibuf(&buf, src->value, src->length);

    if (decode_TLV(&raw_val, &buf)) {
        return -1;
    } else if (raw_val.type != TAG_SEQUENCE) {
        return -1;
    }

    init_ibuf(&buf, raw_val.value, raw_val.length);

    /* engine ID */
    if (decode_TLV(&raw_val, &buf)) {
        return -1;
    } else if (raw_val.type != TAG_OCTETSTRING) {
        return -1;
    } else if (raw_val.length > MAX_ENGINE_ID_LENGTH) {
        return -1;
    }
    memcpy(params->authoritative_engine_id, raw_val.value, raw_val.length);
    params->authoritative_engine_id_len = raw_val.length;

    /* engine boots */
    if (decode_TLV(&raw_val, &buf)) {
        return -1;
    } else if (raw_val.type != TAG_INTEGER) {
        return -1;
    }
    params->authoritative_engine_boots = decode_INTEGER(&raw_val);

    /* engine time */
    if (decode_TLV(&raw_val, &buf)) {
        return -1;
    } else if (raw_val.type != TAG_INTEGER) {
        return -1;
    }
    params->authoritative_engine_time = decode_INTEGER(&raw_val);

    /* user name */
    if (decode_TLV(&raw_val, &buf)) {
        return -1;
    } else if (raw_val.type != TAG_OCTETSTRING) {
        return -1;
    } else if (raw_val.length >= MAX_USER_NAME_LENGTH) {
        return -1;
    }
    memcpy(params->user_name, raw_val.value, raw_val.length);
    params->user_name[raw_val.length] = '\0';

    /* authentication params */
    if (decode_TLV(&raw_val, &buf)) {
        return -1;
    } else if (raw_val.type != TAG_OCTETSTRING) {
        return -1;
    } else if (raw_val.length > MAX_AUTHENTICATION_PARAMETERS) {
        return -1;
    }
    memcpy(params->authentication_parameters, raw_val.value, raw_val.length);
    params->authentication_parameters_len = raw_val.length;

    /* privacy params */
    if (decode_TLV(&raw_val, &buf)) {
        return -1;
    } else if (raw_val.type != TAG_OCTETSTRING) {
        return -1;
    } else if (raw_val.length > MAX_PRIVACY_PARAMETERS) {
        return -1;
    }
    memcpy(params->privacy_parameters, raw_val.value, raw_val.length);
    params->privacy_parameters_len = raw_val.length;
    return 0;
}

int encode_usm_security_parameters(const SnmpUSMSecurityParameters *params, buf_t *dst)
{
    unsigned int mark = dst->pos;

    asn1int_t engine_time = params->authoritative_engine_time;
    asn1int_t engine_boots = params->authoritative_engine_boots;

    if (encode_OCTET_STRING(dst, params->privacy_parameters, params->privacy_parameters_len)) {
        return -1;
    } else if (encode_OCTET_STRING(dst, params->authentication_parameters,
            params->authentication_parameters_len)) {
        return -1;
    } else if (encode_OCTET_STRING(dst, (unsigned char *) params->user_name,
            strnlen((char *) params->user_name, MAX_USER_NAME_LENGTH))) {
        return -1;
    } else if (encode_INTEGER(dst, &engine_time, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    } else if (encode_INTEGER(dst, &engine_boots, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    } else if (encode_OCTET_STRING(dst, params->authoritative_engine_id,
            params->authoritative_engine_id_len)) {
        return -1;
    } else if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED)) {
        return -1;
    } else if (encode_TLV(dst, mark, TAG_OCTETSTRING, FLAG_UNIVERSAL)) {
        return -1;
    }

    return 0;
}

int decode_snmp_scoped_pdu(const asn1raw_t *src, SnmpScopedPDU *pdu)
{
    if (src->type != TAG_SEQUENCE) {
        return -1;
    }

    buf_t buf;
    asn1raw_t raw_tlv;
    init_ibuf(&buf, src->value, src->length);

    /* context engine ID */
    if (decode_TLV(&raw_tlv, &buf)) {
        return -1;
    } else if (raw_tlv.type
            != TAG_OCTETSTRING|| raw_tlv.length >= MAX_CONTEXT_ENGINE_ID) {
        return -1;
    }
    memcpy(pdu->context_engine_id, raw_tlv.value, raw_tlv.length);
    pdu->context_engine_id_len = raw_tlv.length;

    /* context name */
    if (decode_TLV(&raw_tlv, &buf)) {
        return -1;
    } else if (raw_tlv.type
            != TAG_OCTETSTRING|| raw_tlv.length >= MAX_CONTEXT_ENGINE_NAME) {
        return -1;
    }
    memcpy(pdu->context_engine_name, raw_tlv.value, raw_tlv.length);
    pdu->context_engine_name_len = raw_tlv.length;

    /* PDU type */
    if (decode_TLV(&raw_tlv, &buf)) {
        return -1;
    } else if (buf.pos != buf.size) {
        return -1;
    } else if ((pdu->type = get_pdu_type(raw_tlv.type | raw_tlv.flags)) == -1) {
        return -1;
    }

    init_ibuf(&buf, raw_tlv.value, raw_tlv.length);

    /* request ID */
    if (decode_TLV(&raw_tlv, &buf)) {
        return -1;
    } else if (raw_tlv.type != TAG_INTEGER) {
        return -1;
    }
    pdu->request_id = decode_INTEGER(&raw_tlv);

    if (pdu->type == GET_BULK) {
        if (decode_TLV(&raw_tlv, &buf)) {
            return -1;
        } else if (raw_tlv.type != TAG_INTEGER) {
            return -1;
        }
        pdu->non_repeaters = decode_INTEGER(&raw_tlv);

        if (decode_TLV(&raw_tlv, &buf)) {
            return -1;
        } else if (raw_tlv.type != TAG_INTEGER) {
            return -1;
        }
        pdu->max_repetitions = decode_INTEGER(&raw_tlv);
    } else {
        if (decode_TLV(&raw_tlv, &buf)) {
            return -1;
        } else if (raw_tlv.type != TAG_INTEGER) {
            return -1;
        } else if ((pdu->error_status = get_error_status(
                decode_INTEGER(&raw_tlv))) == -1) {
            return -1;
        }

        if (decode_TLV(&raw_tlv, &buf)) {
            return -1;
        } else if (raw_tlv.type != TAG_INTEGER) {
            return -1;
        }
        pdu->error_index = decode_INTEGER(&raw_tlv);
    }

    /* variable bindings */
    if (decode_TLV(&raw_tlv, &buf)) {
        return -1;
    } else if (buf.pos != buf.size) {
        return -1;
    }

    init_ibuf(&buf, raw_tlv.value, raw_tlv.length);
    pdu->num_of_bindings = 0;

    while (buf.pos < buf.size) {
        if (pdu->num_of_bindings >= MAX_SNMP_VAR_BINDINGS) {
            return -1;
        } else if (decode_TLV(&raw_tlv, &buf)) {
            return -1;
        } else if (decode_variable_binding(&raw_tlv,
                &pdu->bindings[pdu->num_of_bindings++])) {
            return -1;
        }
    }

    return 0;
}

int encode_snmp_scoped_pdu(const SnmpScopedPDU *pdu, buf_t *dst)
{
    unsigned int mark = dst->pos;

    /* variable bindings */
    for (int i = pdu->num_of_bindings - 1; i >= 0; i--) {
        if (encode_variable_binding(&pdu->bindings[i], dst)) {
            return -1;
        }
    }
    if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED)) {
        return -1;
    }

    /* error indication */
    asn1int_t error_index = pdu->error_index;
    if (encode_INTEGER(dst, &error_index, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    }

    asn1int_t error_status = pdu->error_status;
    if (encode_INTEGER(dst, &error_status, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    }

    /* response ID */
    asn1int_t response_id = pdu->request_id;
    if (encode_INTEGER(dst, &response_id, TAG_INTEGER, FLAG_UNIVERSAL)) {
        return -1;
    }
    if (encode_TLV(dst, mark, 0x3f & pdu->type, FLAG_CONTEXT)) {
        return -1;
    }

    /* context name/id */
    if (encode_OCTET_STRING(dst, pdu->context_engine_name,
            pdu->context_engine_name_len)) {
        return -1;
    } else if (encode_OCTET_STRING(dst, pdu->context_engine_id,
            pdu->context_engine_id_len)) {
        return -1;
    } else if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED)) {
        return -1;
    }

    return 0;
}

SnmpVariableBinding *add_variable_binding(SnmpScopedPDU *pdu)
{
    if (pdu->num_of_bindings >= MAX_SNMP_VAR_BINDINGS) {
        return NULL;
    }

    return &pdu->bindings[pdu->num_of_bindings++];
}

#ifdef DEBUG
uint8_t *get_pdu_type_name(SnmpPduType type)
{
    switch (type) {
        case GET: {
            return "get request";
        }

        case GET_NEXT: {
            return "get next request";
        }

        case RESPONSE: {
            return "response";
        }

        case SET: {
            return "set request";
        }

        case GET_BULK: {
            return "get bulk request";
        }

        case INFORM: {
            return "inform event";
        }

        case TRAP: {
            return "trap event";
        }

        case REPORT: {
            return "report";
        }

        default: {
            return "N/A";
        }
    }
}

uint8_t *get_error_status_name(SnmpErrorStatus error_status)
{
    switch (error_status) {
        case NO_ERROR: {
            return "no errors";
        }

        case TOO_BIG: {
            return "PDU too big";
        }

        case NO_SUCH_NAME: {
            return "no such name";
        }

        case BAD_VALUE: {
            return "bad value";
        }

        case READ_ONLY: {
            return "read-only";
        }

        case GENERAL_ERROR: {
            return "general error";
        }

        case NO_ACCESS: {
            return "no access";
        }

        case WRONG_TYPE: {
            return "wrong type";
        }

        case WRONG_LENGTH: {
            return "wrong length";
        }

        case WRONG_ENCODING: {
            return "wrong encoding";
        }

        case WRONG_VALUE: {
            return "wrong value";
        }

        case NO_CREATION: {
            return "no creation";
        }

        case INCONSISTENT_VALUE: {
            return "inconsistent value";
        }

        case RESOURCE_UNAVAILABLE: {
            return "resource unavailable";
        }

        case COMMIT_FAILED: {
            return "commit failed";
        }

        case UNDO_FAILED: {
            return "undo failed";
        }

        case AUTHORIZATION_ERROR: {
            return "authorization error";
        }

        case NOT_WRITABLE: {
            return "not writable";
        }

        case INCONSISTENT_NAME: {
            return "inconsistent name";
        }

        default: {
            return "N/A";
        }
    }
}

void dump_snmp_scoped_pdu(const SnmpScopedPDU *pdu)
{
    syslog(LOG_DEBUG, ">> pdu type : %s", get_pdu_type_name(pdu->type));
    syslog(LOG_DEBUG, ">> request id : %"PRIu32, pdu->request_id);

    size_t buf_size = 3 + max(MAX_CONTEXT_ENGINE_ID, MAX_CONTEXT_ENGINE_NAME)
            << 1;
    uint8_t buf[buf_size];
    if (pdu->context_engine_id_len > 0
            && to_hex(pdu->context_engine_id, pdu->context_engine_id_len, buf,
                    buf_size) >= 0) {
        syslog(LOG_DEBUG, ">> context engine id : %s", buf);
    } else {
        syslog(LOG_DEBUG, ">> context engine id : N/A", buf);
    }
    if (pdu->context_engine_name_len > 0
            && to_hex(pdu->context_engine_name, pdu->context_engine_name_len,
                    buf, buf_size) >= 0) {
        syslog(LOG_DEBUG, ">> context engine name : %s", buf);
    } else {
        syslog(LOG_DEBUG, ">> context engine name : N/A", buf);
    }

    if (pdu->type == GET_BULK) {
        syslog(LOG_DEBUG, ">> non-repeaters : %"PRIu32, pdu->non_repeaters);
        syslog(LOG_DEBUG, ">> max repetitions : %"PRIu32, pdu->max_repetitions);
    } else {
        syslog(LOG_DEBUG, ">> error status : %s",
                get_error_status_name(pdu->error_status));
        syslog(LOG_DEBUG, ">> error index : %"PRIu32, pdu->error_index);
    }

    if (pdu->num_of_bindings <= 0) {
        syslog(LOG_DEBUG, ">> no variable bindings");
    } else {
        syslog(LOG_DEBUG, ">> variable bindings:");
        for (int i = 0; i < pdu->num_of_bindings; i++) {
            dump_variable_binding(&pdu->bindings[i]);
        }
    }
}

void dump_snmp_pdu(const SnmpPDU *pdu, const int scoped_pdu_decrypted)
{
    syslog(LOG_DEBUG, ">> message id : %"PRIu32, pdu->message_id);
    syslog(LOG_DEBUG, ">> max PDU size : %"PRIu32, pdu->max_size);
    syslog(LOG_DEBUG, ">> encrypted : %s", pdu->is_encrypted ? "true" : "false");
    syslog(LOG_DEBUG, ">> authenticated : %s", pdu->is_authenticated ? "true" : "false");
    syslog(LOG_DEBUG, ">> requires response : %s", pdu->requires_response ? "true" : "false");
    syslog(LOG_DEBUG, ">>> security parameters:");
    const size_t sec_buf_len = 3 + max(max(MAX_ENGINE_ID_LENGTH,MAX_USER_NAME_LENGTH),
          max(MAX_AUTHENTICATION_PARAMETERS,MAX_PRIVACY_PARAMETERS)) << 1;
    uint8_t sec_buf[sec_buf_len];
    if (pdu->security_parameters.authoritative_engine_id_len <= 0
            || to_hex(pdu->security_parameters.authoritative_engine_id,
               pdu->security_parameters.authoritative_engine_id_len,
               sec_buf, sec_buf_len) > 0) {
        syslog(LOG_DEBUG, ">> engine id : N/A");
    } else {
        syslog(LOG_DEBUG, ">> engine id : %s", sec_buf);
    }
    syslog(LOG_DEBUG, ">> engine boots/time : %"PRIu32":%"PRIu32,
            pdu->security_parameters.authoritative_engine_boots,
            pdu->security_parameters.authoritative_engine_time);
    syslog(LOG_DEBUG, ">> security name : %s", pdu->security_parameters.user_name);

    if (pdu->security_parameters.authentication_parameters_len <= 0
            || to_hex(pdu->security_parameters.authentication_parameters,
               pdu->security_parameters.authentication_parameters_len,
               sec_buf, sec_buf_len) > 0) {
        syslog(LOG_DEBUG, ">> authentication tag : N/A");
    } else {
        syslog(LOG_DEBUG, ">> authentication tag : %s", sec_buf);
    }

    if (pdu->security_parameters.privacy_parameters_len <= 0
            || to_hex(pdu->security_parameters.privacy_parameters,
               pdu->security_parameters.privacy_parameters_len,
               sec_buf, sec_buf_len) > 0) {
        syslog(LOG_DEBUG, ">> privacy parameters : N/A");
    } else {
        syslog(LOG_DEBUG, ">> privacy parameters : %s", sec_buf);
    }

    if (scoped_pdu_decrypted) {
        dump_snmp_scoped_pdu(pdu->scoped_pdu.decrypted_pdu);
    } else {
        size_t hex_val_size = 3 + pdu->scoped_pdu.encrypted_pdu.len << 1;
        uint8_t *hex_val = malloc(sizeof(uint8_t) * hex_val_size);
        if (hex_val == NULL) {
            syslog(LOG_DEBUG, ">> scoped PDU : N/A");
        } else {
            if (to_hex(pdu->scoped_pdu.encrypted_pdu.data,
                    pdu->scoped_pdu.encrypted_pdu.len, hex_val, hex_val_size)) {
                syslog(LOG_DEBUG, ">> scoped PDU : %s", hex_val);
            } else {
                syslog(LOG_DEBUG, ">> scoped PDU : N/A");
            }
            free(hex_val);
        }
    }
}
#endif
