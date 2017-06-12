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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO NOTIFICATION SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <string.h>
#include <mqueue.h>
#include <errno.h>
#include <stdint.h>
#include <syslog.h>
#include <time.h>

#include "snmp-agent/agent-notification-builder.h"
#include "snmp-agent/agent-notification.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/snmp-pdu.h"

#define SNMP_OID_SNMPV2_TRAP_OBJS_PREFIX   SNMP_OID_SNMPMODULES,1,1,4
#define DEFAULT_TRAP_LEN    16

/* maximum amount of generic arguments included in trap varlist */
#define MAX_ARGUMENTS   8

static int add_var_bindings(uint16_t, uint16_t, buf_t *, SnmpScopedPDU *);
static int add_generic_arguments(const agent_notification *, buf_t *, SnmpScopedPDU *);

static const SubOID snmp_trap_oid[] = { SNMP_OID_SNMPV2_TRAP_OBJS_PREFIX, 1, 0 };
static const size_t snmp_trap_oid_len = OID_LENGTH(snmp_trap_oid);

/* The assigned enterprise number for notifications. */
static const SubOID trap_notification_oid[] = { SNMP_OID_ENTERPRISE_MIB, 2 };
static const size_t trap_notification_oid_len = OID_LENGTH(trap_notification_oid);

/* custom traps */
static agent_notification const **custom_trap;
static size_t custom_trap_len = 0;
static size_t custom_trap_max = 0;

/* RFC-defined OIDs */
static const SubOID trap_cold_start_oid[] = { SNMP_OID_SNMPMODULES, 1, 1, 5, 1 };
static const SubOID trap_authentication_failure_oid[] =
    { SNMP_OID_SNMPMODULES, 1, 1, 5, 5 };

/* notifications with non-standard OID list */
const agent_notification trap_auth_failed = {
    .code_1 = 0x6300,
    .code_2 = 0x0407,
    .oid = trap_authentication_failure_oid,
    .oid_len = OID_LENGTH(trap_authentication_failure_oid),
    .add_arguments = add_generic_arguments
};

const agent_notification trap_power_up = {
    .code_1 = 0x0002,
    .code_2 = 0x0000,
    .oid = trap_cold_start_oid,
    .oid_len = OID_LENGTH(trap_cold_start_oid),
    .add_arguments = NULL
};

/* generic notification arguments */
static const SubOID trap_arg_generic_oid[] = { SNMP_OID_ENTERPRISE_MIB, 0, 1, 0 };
static const size_t trap_arg_generic_oid_len = OID_LENGTH(trap_arg_generic_oid);

/* sysUptime.0 */
static const SubOID sys_uptime_oid[] = { SNMP_OID_MIB2, 1, 3, 0 };

static const char *default_source = "unknown";

int init_notification_builder(void)
{
    custom_trap = malloc(DEFAULT_TRAP_LEN * sizeof(agent_notification *));
    if (custom_trap == NULL)
        return -1;
    custom_trap_max = DEFAULT_TRAP_LEN;
    custom_trap[custom_trap_len++] = &trap_auth_failed;
    custom_trap[custom_trap_len++] = &trap_power_up;
    return 0;
}

int add_notification_type(const agent_notification *type)
{
    if (custom_trap == NULL)
        return -1;

    if (custom_trap_len >= custom_trap_max) {
        agent_notification const **custom_trap_tmp =
            realloc(custom_trap, sizeof(agent_notification *) * custom_trap_max << 1);
        if (custom_trap_tmp == NULL)
            return -1;
        custom_trap = custom_trap_tmp;
        custom_trap_max <<= 1;
    }

    custom_trap[custom_trap_len++] = type;
    return 0;
}

int build_authentication_failure_notification(const char *source, buf_t *buf)
{
    asn1int_t version = NOTIFICATION_VERSION;
    uint8_t flags = 0x00;
    asn1int_t trap_code_2 = trap_auth_failed.code_2;
    asn1int_t trap_code_1 = trap_auth_failed.code_1;

    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    /* continue even if fetching the system time fails */
    int mark = buf->pos;
    source = source ?: default_source;

    CHECK_TRAP_ENC_RESULT(encode_OCTET_STRING(buf, (uint8_t *) source, strlen(source)),
            "notification source");
    CHECK_TRAP_ENC_RESULT(encode_TLV(buf, mark, TAG_SEQUENCE, FLAG_STRUCTURED),
            "notification arguments");
    CHECK_TRAP_ENC_RESULT(encode_INTEGER(buf, &trap_code_2, TAG_INTEGER,
            FLAG_UNIVERSAL), "trap code");
    CHECK_TRAP_ENC_RESULT(encode_INTEGER(buf, &trap_code_1, TAG_INTEGER,
        FLAG_UNIVERSAL), "trap code");
    CHECK_TRAP_ENC_RESULT(encode_UNSIGNED64(buf,
        (time.tv_sec * 1000) + (time.tv_nsec / 1000000), TAG_INTEGER,
        FLAG_UNIVERSAL), "notification time stamp");
    CHECK_TRAP_ENC_RESULT(encode_BITSTRING(buf, &flags), "notification flags");
    CHECK_TRAP_ENC_RESULT(encode_INTEGER(buf, &version, TAG_INTEGER, FLAG_UNIVERSAL),
            "notification version number");
    CHECK_TRAP_ENC_RESULT(encode_TLV(buf, mark, TAG_SEQUENCE, FLAG_STRUCTURED),
            "notification");

    return 0;
}

int build_snmp_notification_scoped_pdu(buf_t *source, SnmpScopedPDU *scoped_pdu)
{
    asn1raw_t tlv;
    CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, source),
            "notification sequence parse exception");
    CHECK_TRAP_DEC_RESULT(tlv.type != TAG_SEQUENCE, "wrong notification tag");
    init_ibuf(source, tlv.value, tlv.length);

    /* check version */
    CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, source),
            "notification version parse exception");
    CHECK_TRAP_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong version tag");
    asn1int_t version = decode_INTEGER(&tlv);
    if (version != NOTIFICATION_VERSION) {
        syslog(LOG_WARNING,
            "failed to parse incoming notification : received version %d.", (int) version);
        return -1;
    }

    /* skip flags and timestamp */
    CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, source),
            "notification flags parse exception");
    CHECK_TRAP_DEC_RESULT(tlv.type != TAG_BITSTRING, "wrong flags tag");
    CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, source),
            "notification time stamp parse exception");
    CHECK_TRAP_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong time stamp tag");

    /* trap code 1 */
    CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, source), "trap code parse exception");
    CHECK_TRAP_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong trap code tag");
    uint16_t trap_code_1 = decode_INTEGER(&tlv);

    /* trap code 2 */
    CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, source), "trap code parse exception");
    CHECK_TRAP_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong trap code tag");
    uint16_t trap_code_2 = decode_INTEGER(&tlv);

    /* arguments */
    CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, source),
            "notification arguments parse exception");
    CHECK_TRAP_DEC_RESULT(tlv.type != TAG_SEQUENCE,
            "wrong notification arguments tag");
    init_ibuf(source, tlv.value, tlv.length);

    /* RFC 3416 mandates inclusion of sysUpTime.0 */
    /* NOTE: some notifications are generated retroactively
     * (e.g. offline tamper notifications), in which case this uptime field
     * is not correct. */
    NEW_VAR_BINDING(uptime_binding, scoped_pdu)
    memcpy(uptime_binding->oid.subid, sys_uptime_oid, sizeof(sys_uptime_oid));
    uptime_binding->oid.len = OID_LENGTH(sys_uptime_oid);
    uptime_binding->type = SMI_TYPE_TIME_TICKS;
    uptime_binding->value.unsigned_integer = 100 * get_uptime();

    /* snmpTrapOID.0 and additional arguments */
    if (add_var_bindings(trap_code_1, trap_code_2, source, scoped_pdu)) {
        syslog(LOG_WARNING, "failed to add trap oid and arguments");
        return -1;
    }

    return 0;
}

static int add_var_bindings(uint16_t trap_code_1, uint16_t trap_code_2,
        buf_t *buf, SnmpScopedPDU *scoped_pdu)
{
    NEW_VAR_BINDING(binding, scoped_pdu)

    binding->type = SMI_TYPE_OID;
    binding->oid.len = snmp_trap_oid_len;
    memcpy(binding->oid.subid, snmp_trap_oid, sizeof(snmp_trap_oid));

    /* use custom arguments where possible */
    for (int i = 0; i < custom_trap_len; i++) {
        if (custom_trap[i]->code_1 == trap_code_1 &&
                custom_trap[i]->code_2 == trap_code_2) {
            memcpy(binding->value.oid.subid, custom_trap[i]->oid,
                    custom_trap[i]->oid_len * sizeof(SubOID));
            binding->value.oid.len = custom_trap[i]->oid_len;
            if (custom_trap[i]->add_arguments == NULL)
                return 0;
            return custom_trap[i]->add_arguments(custom_trap[i], buf, scoped_pdu);
        }
    }

    /* generic enterprise OID consists of
     * <trap_notification_oid>.<trap_code_1>.<trap_code_2>.1 */
    memcpy(binding->value.oid.subid, trap_notification_oid,
            sizeof(trap_notification_oid));
    binding->value.oid.len = trap_notification_oid_len;
    binding->value.oid.subid[binding->value.oid.len++] = trap_code_1;
    binding->value.oid.subid[binding->value.oid.len++] = trap_code_2;
    binding->value.oid.subid[binding->value.oid.len++] = 1;
    return add_generic_arguments(NULL, buf, scoped_pdu);
}

static int add_generic_arguments(const agent_notification *notification,
        buf_t *buf, SnmpScopedPDU *scoped_pdu)
{
    SubOID argument_oid[MAX_OID_LEN];
    memcpy(argument_oid, trap_arg_generic_oid, sizeof(trap_arg_generic_oid));
    size_t argument_oid_len = trap_arg_generic_oid_len + 1;

    for (int i = 0; i < MAX_ARGUMENTS && buf->pos < buf->size; i++) {
        asn1raw_t tlv;
        CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, buf),
                "notification argument parse exception");
        NEW_VAR_BINDING(var_binding, scoped_pdu)

        memcpy(var_binding->oid.subid, argument_oid, sizeof(argument_oid));
        var_binding->oid.subid[argument_oid_len - 1] = i;
        var_binding->oid.len = argument_oid_len;
        switch (tlv.type) {
            case TAG_NULLTAG: {
                var_binding->type = SMI_TYPE_OCTET_STRING;
                var_binding->value.octet_string.len = 0;
                break;
            }

            case TAG_BOOLEAN: {
                var_binding->type = SMI_TYPE_INTEGER_32;
                var_binding->value.integer = decode_BOOLEAN(&tlv) ? 1 : 0;
                break;
            }

            case TAG_INTEGER: {
                var_binding->type = SMI_TYPE_COUNTER_64;
                var_binding->value.counter64 = decode_INTEGER(&tlv);
                break;
            }

            case TAG_ENUMERATED: {
                var_binding->type = SMI_TYPE_INTEGER_32;
                var_binding->value.integer = decode_INTEGER(&tlv);
                break;
            }

            case TAG_OID: {
                var_binding->type = SMI_TYPE_OID;
                if (decode_OID(&tlv, &var_binding->value.oid)) {
                    syslog(LOG_WARNING, "notification contains illegal OID");
                    SET_OID(var_binding->value.oid, 0, 0);
                }
                break;
            }

            case TAG_OCTETSTRING: {
                var_binding->type = SMI_TYPE_OCTET_STRING;
                var_binding->value.octet_string.octets = tlv.value;
                var_binding->value.octet_string.len = tlv.length;
                break;
            }

            default: {
                syslog(LOG_WARNING,
                    "unexpected notification argument type %02x", tlv.type);
            }
        }
    }

    return 0;
}
