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

#ifndef SRC_SNMP_CORE_SNMP_TYPES_H_
#define SRC_SNMP_CORE_SNMP_TYPES_H_

#include <stdlib.h>
#include <string.h>
#include "snmp-core/tinyber.h"

/** SMI defined types */
typedef enum {
    SMI_TYPE_OCTET_STRING = 0x04,
    SMI_TYPE_NULL = 0x05,
    SMI_TYPE_OID = 0x06,
    SMI_TYPE_INTEGER_32 = 0x02,
    SMI_TYPE_IP_ADDRESS = 0x40,
    SMI_TYPE_COUNTER_32 = 0x41,
    SMI_TYPE_GAUGE_32 = 0x42,
    SMI_TYPE_TIME_TICKS = 0x43,
    SMI_TYPE_OPAQUE = 0x44,
    SMI_TYPE_COUNTER_64 = 0x46,

    /** error variable bindings */
    SMI_EXCEPT_NO_SUCH_OBJECT = 0x80,
    SMI_EXCEPT_NO_SUCH_INSTANCE = 0x81,
    SMI_EXCEPT_END_OF_MIB_VIEW = 0x82
} SMIType;

/* maximum subIDs in an oid */
#define MAX_OID_LEN	128

#define OID_LENGTH(x)  (sizeof(x)/sizeof(SubOID))
#define OID_SEQ_LENGTH(...) OID_LENGTH(((SubOID[]){__VA_ARGS__}))

#define SET_OID(oid, ...) do { \
    (oid).len = OID_SEQ_LENGTH(__VA_ARGS__); \
    init_OID(&(oid), (oid).len, __VA_ARGS__); \
} while (0)

#define COPY_OID(dst, src) do { \
    memcpy(dst, src, sizeof(SubOID) * (src)->len); \
    (dst)->len = (src)->len; \
} while (0)

#define SET_OID_BIND(binding, ...) do { \
    (binding)->type = SMI_TYPE_OID; \
    SET_OID((binding)->value.oid, __VA_ARGS__); \
} while (0)

#define COPY_OID_BIND(binding, src) do { \
    (binding)->type = SMI_TYPE_OID; \
    COPY_OID(&(binding)->value.oid, src); \
} while (0)

#define SET_IP4_ADDRESS_BIND(binding, address) do { \
    (binding)->type = SMI_TYPE_IP_ADDRESS; \
    (binding)->value.ip_address[0] = (address)[0]; \
    (binding)->value.ip_address[1] = (address)[1]; \
    (binding)->value.ip_address[2] = (address)[2]; \
    (binding)->value.ip_address[3] = (address)[3]; \
} while (0)

#define SET_OCTET_STRING_BIND(binding, val, val_len) do { \
    (binding)->type = SMI_TYPE_OCTET_STRING; \
    (binding)->value.octet_string.octets = (uint8_t *) (val); \
    (binding)->value.octet_string.len = (val_len); \
} while (0)

#define SET_OPAQUE_BIND(binding, val, val_len) do { \
    (binding)->type = SMI_TYPE_OPAQUE; \
    (binding)->value.octet_string.octets = (uint8_t *) (val); \
    (binding)->value.octet_string.len = (val_len); \
} while (0)

#define SET_UTF8_STRING_BIND(binding, val) do { \
    (binding)->type = SMI_TYPE_OCTET_STRING; \
    (binding)->value.octet_string.octets = (uint8_t *) (val); \
    (binding)->value.octet_string.len = \
        strlen((char *) (binding)->value.octet_string.octets); \
} while (0)

#define SET_INTEGER_BIND(binding, val) do { \
    (binding)->type = SMI_TYPE_INTEGER_32; \
    (binding)->value.integer = (val); \
} while (0)

#define SET_UNSIGNED_BIND(binding, val) do { \
    (binding)->type = SMI_TYPE_COUNTER_32; \
    (binding)->value.unsigned_integer = (val); \
} while (0)

#define SET_UNSIGNED64_BIND(binding, val) do { \
    (binding)->type = SMI_TYPE_COUNTER_64; \
    (binding)->value.counter64 = (val); \
} while (0)

#define SET_GAUGE_BIND(binding, val) do { \
    (binding)->type = SMI_TYPE_GAUGE_32; \
    (binding)->value.unsigned_integer = (val); \
} while (0)

#define SET_TIME_TICKS_BIND(binding, val) do { \
    (binding)->type = SMI_TYPE_TIME_TICKS; \
    (binding)->value.unsigned_integer = (val); \
} while (0)

#define GET_OCTET_STRING(binding) (binding)->value.octet_string.octets
#define GET_OCTET_STRING_LEN(binding) (binding)->value.octet_string.len

/* limit subID to 32-bit integers */
typedef uint32_t SubOID;

/** object identifier */
typedef struct {

    /* list of sub identifiers */
    SubOID subid[MAX_OID_LEN];

    /* amount of sub identifiers */
    size_t len;

} OID;

/** SNMP variable binding (OID, value/error pair) */
typedef struct {

    /* variable identifier */
    OID oid;

    /* variable type */
    SMIType type;

    /* variable value (not used in case of error) */
    union {
        int32_t integer;
        uint32_t unsigned_integer;
        uint64_t counter64;
        uint8_t ip_address[4];
        struct {
            uint8_t *octets;
            size_t len;
        } octet_string;
        OID oid;
    } value;

} SnmpVariableBinding;

/**
 * init_OID - Initialize subOID list with given arguments.
 *
 * @param oid IN/OUT - destination OID.
 * @param len IN - length of varargs list.
 * @param varargs IN - list of sub OIDs.
 */
__attribute__((visibility("default")))
void init_OID(OID *oid, size_t len, ...);

/**
 * decode_OID - Extracts an OID from the given BER encoded TLV.
 *
 * @param src IN - TLV containing OID.
 * @param oid OUT - destination output.
 *
 * @return 0 on success, -1 on parse error.
 */
__attribute__((visibility("default")))
int decode_OID(const asn1raw_t *src, OID *oid);

/**
 * encode_OID - Encodes OID to BER TLV.
 *
 * @param oid IN - OID to be encoded.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 on encoding error.
 */
__attribute__((visibility("default")))
int encode_OID(const OID *oid, buf_t *dst);

/**
 * encode_OID_to_dotted_string - Encodes OID to dotted string.
 *
 * @param oid IN - OID to be encoded.
 * @param buf OUT - destination output.
 * @param buf_len IN - destination output size.
 *
 * @return 0 on success, -1 on encoding error.
 */
__attribute__((visibility("default")))
int encode_OID_to_dotted_string(const OID *oid, uint8_t *buf, size_t buf_len);

/**
 * prefix_compare_OID - Check if a given OID is a prefix of another OID
 *
 * @parm o1 IN - OID prefix to check against
 * @parm o2 IN - OID which should be covered by the prefix.
 *
 * @return 0 on prefix match, -1 when o2 is greater than the given prefix,
 * 1 otherwise.
 */
__attribute__((visibility("default")))
int prefix_compare_OID(const OID *o1, const OID *o2);

/**
 * compare_OID - Compares OIDs in lexicographic ordering
 *
 * @parm o1 IN - first OID
 * @parm o2 IN - second OID
 *
 * @return 0 on equality, -1 when o1 is less than o2, 1 otherwise.
 */
__attribute__((visibility("default")))
int compare_OID(const OID *o1, const OID *o2);

/**
 * decode_variable_binding - Extracts variable binding from given BER encoded TLV.
 *
 * @param src IN - TLV containing variable binding.
 * @param binding OUT - destination variable binding.
 *
 * @return 0 on success, -1 on parse error.
 * octet-string (if present) point to the source memory.
 */
int decode_variable_binding(const asn1raw_t *src, SnmpVariableBinding *binding);

/**
 * encode_variable_binding - Encodes a variable binding to a BER TLV.
 *
 * @param binding IN - variable binding to be encoded.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 on encoding error.
 */
int encode_variable_binding(const SnmpVariableBinding *binding, buf_t *dst);

/**
 * dump_variable_binding - Dumps the content of the variable binding to syslog.
 *
 * @param binding IN - binding to be logged.
 */
void dump_variable_binding(const SnmpVariableBinding *binding);

#endif /* SRC_SNMP_CORE_SNMP_TYPES_H_ */
