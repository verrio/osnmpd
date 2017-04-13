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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include "snmp-core/snmp-core.h"
#include "snmp-core/snmp-types.h"
#include "snmp-core/tinyber.h"
#include "snmp-core/utils.h"

void init_OID(OID *oid, size_t len, ...)
{
    va_list varargs;
    va_start(varargs, len);
    for (unsigned int i = 0; i < len; i++) {
        oid->subid[i] = va_arg(varargs, SubOID);
    }
    va_end(varargs);
}

int decode_OID(const asn1raw_t *src, OID *oid)
{
    if (src->length > MAX_OID_LEN - 1) {
        return -1;
    } else if (src->length <= 0) {
        oid->subid[0] = 0x0;
        oid->subid[1] = 0x0;
        oid->len = 2;
        return 0;
    }

    oid->subid[0] = src->value[0] / 40;
    oid->subid[1] = src->value[0] % 40;
    oid->len = 2;

    int sub_id = 0;
    unsigned int c = 1;
    while (c < src->length) {
        sub_id = (sub_id << 7) + (src->value[c] & 0x7f);
        if ((src->value[c++] & 0x80) == 0x00) {
            oid->subid[oid->len++] = sub_id;
            sub_id = 0;
        }
    }

    return 0;
}

static int emit_byte(uint8_t byte, buf_t *dst)
{
    if (dst->pos < 1) {
        return -1;
    } else {
        dst->buffer[--dst->pos] = byte;
        return 0;
    }
}

int encode_OID(const OID *oid, buf_t *dst)
{
    int mark = dst->pos;
    if (oid->len > 2) {
        int sub_id = oid->len - 1;
        while (sub_id > 1) {
            if (oid->subid[sub_id] < 127) {
                if (emit_byte(oid->subid[sub_id], dst)) {
                    return -1;
                }
            } else {
                uint32_t sub_id_buf = oid->subid[sub_id];

                /* last byte has high bit unset */
                if (emit_byte(sub_id_buf & 0x7f, dst)) {
                    return -1;
                }
                sub_id_buf >>= 7;

                /* leading bytes have high bit set */
                while (sub_id_buf > 0) {
                    if (emit_byte((sub_id_buf & 0x7f) | 0x80, dst)) {
                        return -1;
                    }
                    sub_id_buf >>= 7;
                }
            }
            sub_id--;
        }
    }
    if (oid->len > 1) {
        if (emit_byte(oid->subid[0] * 0x28 + oid->subid[1], dst)) {
            return -1;
        }
    } else if (oid->len > 0) {
        if (emit_byte(oid->subid[0] * 0x28, dst)) {
            return -1;
        }
    }

    if (encode_TLV(dst, mark, TAG_OID, FLAG_UNIVERSAL)) {
        return -1;
    }

    return 0;
}

int encode_OID_to_dotted_string(const OID *oid, uint8_t *buf, size_t buf_len)
{
    for (unsigned int i = 0; i < oid->len - 1; i++) {
        int written = snprintf((char *) buf, buf_len, "%"PRIu32".", oid->subid[i]);
        if (written <= 0) {
            return -1;
        }
        buf += written;
        buf_len -= written;
    }

    if (oid->len > 0) {
        if (snprintf((char *) buf, buf_len, "%"PRIu32, oid->subid[oid->len - 1]) <= 0) {
            return -1;
        }
    }

    return 0;
}

int compare_OID(const OID *o1, const OID *o2)
{
    for (unsigned int i = 0; i < min(o1->len, o2->len); i++) {
        if (o1->subid[i] < o2->subid[i]) {
            return -1;
        } else if (o1->subid[i] > o2->subid[i]) {
            return 1;
        }
    }

    if (o1->len < o2->len) {
        return -1;
    } else if (o1->len > o2->len) {
        return 1;
    }

    return 0;
}

int prefix_compare_OID(const OID *o1, const OID *o2)
{
    for (unsigned int i = 0; i < min(o1->len, o2->len); i++) {
        if (o1->subid[i] < o2->subid[i]) {
            return -1;
        } else if (o1->subid[i] > o2->subid[i]) {
            return 1;
        }
    }

    if (o1->len > o2->len) {
        return 1;
    }

    return 0;
}

int decode_variable_binding(const asn1raw_t *src, SnmpVariableBinding *binding)
{
    if (src->type != TAG_SEQUENCE) {
        return -1;
    }

    buf_t buf;
    init_ibuf(&buf, src->value, src->length);

    /* decode OID */
    asn1raw_t raw_oid;
    if (decode_TLV(&raw_oid, &buf)) {
        return -1;
    } else if (raw_oid.type != TAG_OID) {
        return -1;
    } else if (decode_OID(&raw_oid, &binding->oid)) {
        return -1;
    }

    /* decode variable */
    asn1raw_t raw_var;
    if (decode_TLV(&raw_var, &buf)) {
        return -1;
    } else if (buf.pos != buf.size) {
        return -1;
    }

    binding->type = raw_var.flags | raw_var.type;
    switch (binding->type) {
        case SMI_TYPE_OPAQUE:
        case SMI_TYPE_OCTET_STRING: {
            binding->value.octet_string.octets = raw_var.value;
            binding->value.octet_string.len = raw_var.length;
            break;
        }

        case SMI_TYPE_NULL: {
            if (raw_var.length != 0) {
                return -1;
            }
            break;
        }

        case SMI_TYPE_OID: {
            if (decode_OID(&raw_var, &binding->value.oid)) {
                return -1;
            }
            break;
        }

        case SMI_TYPE_INTEGER_32: {
            binding->value.integer = decode_INTEGER(&raw_var);
            break;
        }

        case SMI_TYPE_IP_ADDRESS: {
            if (raw_var.length != 4) {
                return -1;
            }
            binding->value.ip_address[0] = raw_var.value[0];
            binding->value.ip_address[1] = raw_var.value[1];
            binding->value.ip_address[2] = raw_var.value[2];
            binding->value.ip_address[3] = raw_var.value[3];
            break;
        }

        case SMI_TYPE_COUNTER_32:
        case SMI_TYPE_GAUGE_32:
        case SMI_TYPE_TIME_TICKS: {
            binding->value.unsigned_integer = decode_INTEGER(&raw_var);
            break;
        }

        case SMI_TYPE_COUNTER_64: {
            binding->value.counter64 = decode_INTEGER(&raw_var);
            break;
        }

        case SMI_EXCEPT_NO_SUCH_OBJECT:
        case SMI_EXCEPT_NO_SUCH_INSTANCE:
        case SMI_EXCEPT_END_OF_MIB_VIEW: {
            if (raw_var.length != 0) {
                return -1;
            }
            break;
        }

        default: {
            return -1;
        }
    }

    return 0;
}

int encode_variable_binding(const SnmpVariableBinding *binding, buf_t *dst)
{
    unsigned int mark = dst->pos;

    /* encode variable */
    switch (binding->type) {
        case SMI_TYPE_OPAQUE:
        case SMI_TYPE_OCTET_STRING: {
            if (dst->pos < binding->value.octet_string.len) {
                return -1;
            }
            dst->pos -= binding->value.octet_string.len;
            memcpy(&dst->buffer[dst->pos], binding->value.octet_string.octets,
                    binding->value.octet_string.len);
            if (encode_TLV(dst, mark, binding->type, 0)) {
                return -1;
            }
            break;
        }

        case SMI_TYPE_OID: {
            if (encode_OID(&binding->value.oid, dst)) {
                return -1;
            }
            break;
        }

        case SMI_TYPE_IP_ADDRESS: {
            for (int i = 3; i >= 0; i--) {
                if (emit_byte(binding->value.ip_address[i], dst)) {
                    return -1;
                }
            }
            if (encode_TLV(dst, dst->pos + 4, binding->type, 0)) {
                return -1;
            }
            break;
        }

        case SMI_TYPE_INTEGER_32: {
            asn1int_t val = binding->value.integer;
            if (encode_INTEGER(dst, &val, binding->type, 0)) {
                return -1;
            }
            break;
        }

        case SMI_TYPE_COUNTER_32:
        case SMI_TYPE_GAUGE_32:
        case SMI_TYPE_TIME_TICKS: {
            asn1int_t val = binding->value.unsigned_integer;
            if (encode_INTEGER(dst, &val, binding->type, 0)) {
                return -1;
            }
            break;
        }

        case SMI_TYPE_COUNTER_64: {
            if (encode_UNSIGNED64(dst, binding->value.counter64, binding->type,
                    0)) {
                return -1;
            }
            break;
        }

        case SMI_TYPE_NULL:
        case SMI_EXCEPT_NO_SUCH_OBJECT:
        case SMI_EXCEPT_NO_SUCH_INSTANCE:
        case SMI_EXCEPT_END_OF_MIB_VIEW: {
            if (encode_TLV(dst, dst->pos, binding->type, 0)) {
                return -1;
            }
            break;
        }

        default: {
            return -1;
        }
    }

    /* encode OID */
    if (encode_OID(&binding->oid, dst)) {
        return -1;
    }

    if (encode_TLV(dst, mark, TAG_SEQUENCE, FLAG_STRUCTURED)) {
        return -1;
    }

    return 0;
}

void dump_variable_binding(const SnmpVariableBinding *binding)
{
    size_t oid_buf_len = 1 + (MAX_OID_LEN << 1);
    uint8_t oid_buf[oid_buf_len];

    if (encode_OID_to_dotted_string(&binding->oid, oid_buf, oid_buf_len)) {
        syslog(LOG_DEBUG, ">>> invalid OID : N/A");
        return;
    }

    switch (binding->type) {
        case SMI_TYPE_OPAQUE:
        case SMI_TYPE_OCTET_STRING: {
            if (binding->value.octet_string.len >= 0) {
                size_t hex_val_size = 3 + (binding->value.octet_string.len << 1);
                char *hex_val = malloc(sizeof(char) * hex_val_size);
                if (hex_val == NULL) {
                    return;
                } else if (to_hex(binding->value.octet_string.octets,
                        binding->value.octet_string.len, hex_val, hex_val_size) > 0) {
                    syslog(LOG_DEBUG, ">>> %s : %s", oid_buf, hex_val);
                } else {
                    syslog(LOG_DEBUG, ">>> %s : N/A", oid_buf);
                }
                free(hex_val);
            } else {
                syslog(LOG_DEBUG, ">>> %s : N/A", oid_buf);
            }
            break;
        }

        case SMI_TYPE_NULL: {
            syslog(LOG_DEBUG, ">>> %s : empty", oid_buf);
            break;
        }

        case SMI_TYPE_OID: {
            uint8_t oid_val[oid_buf_len];
            if (encode_OID_to_dotted_string(&binding->value.oid, oid_val, oid_buf_len)) {
                syslog(LOG_DEBUG, ">>> %s : invalid OID", oid_buf);
            } else {
                syslog(LOG_DEBUG, ">>> %s : %s", oid_buf, oid_val);
            }
            break;
        }

        case SMI_TYPE_INTEGER_32: {
            syslog(LOG_DEBUG, ">>> %s : %"PRIi32, oid_buf, binding->value.integer);
            break;
        }

        case SMI_TYPE_IP_ADDRESS: {
            syslog(LOG_DEBUG, ">>> %s : %"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8, oid_buf,
                    binding->value.ip_address[0], binding->value.ip_address[1],
                    binding->value.ip_address[2], binding->value.ip_address[3]);
            break;
        }

        case SMI_TYPE_COUNTER_32:
        case SMI_TYPE_GAUGE_32:
        case SMI_TYPE_TIME_TICKS: {
            syslog(LOG_DEBUG, ">>> %s : %"PRIu32, oid_buf,
                    binding->value.unsigned_integer);
            break;
        }

        case SMI_TYPE_COUNTER_64: {
            syslog(LOG_DEBUG, ">>> %s : %"PRIu64, oid_buf,
                    binding->value.counter64);
            break;
        }

        case SMI_EXCEPT_NO_SUCH_OBJECT: {
            syslog(LOG_DEBUG, ">>> %s : no such object", oid_buf);
            break;
        }

        case SMI_EXCEPT_NO_SUCH_INSTANCE: {
            syslog(LOG_DEBUG, ">>> %s : no such instance", oid_buf);
            break;
        }

        case SMI_EXCEPT_END_OF_MIB_VIEW: {
            syslog(LOG_DEBUG, ">>> %s : end of MIB", oid_buf);
            break;
        }

        default: {
            syslog(LOG_DEBUG, ">>> %s : N/A", oid_buf);
        }
    }
}
