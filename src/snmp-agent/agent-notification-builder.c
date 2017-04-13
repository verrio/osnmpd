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

#define CHECK_ENC_RESULT(x,y) do { \
	int retval = (x); \
	if (retval != 0) { \
		syslog(LOG_WARNING, "failed to encode %s. (return code %d)", y, retval); \
		return -1; \
	} \
} while (0)

#define CHECK_DEC_RESULT(x,y) do { \
	int retval = (x); \
	if (retval != 0) { \
		syslog(LOG_WARNING, "notification decode error: %s. (return code %d)", \
            y, retval); \
		return -1; \
	} \
} while (0)

#define AUTH_FAILURE_NOTIFICATION_CODE     0x6300
#define AUTH_FAILURE_DEVICE_CODE    0x0105

#define SNMP_OID_IF_ENTRY_MIB              1,3,6,1,2,1,2,2,1
#define SNMP_OID_SNMPV2_TRAP_OBJS_PREFIX   SNMP_OID_SNMPMODULES,1,1,4

static const SubOID snmp_trap_oid[] = { SNMP_OID_SNMPV2_TRAP_OBJS_PREFIX, 1, 0 };
static const size_t snmp_trap_oid_len = OID_LENGTH(snmp_trap_oid);

/* The assigned enterprise number for notifications. */
static const SubOID trap_notification_oid[] = { SNMP_OID_ENTERPRISE_MIB, 2 };
static const size_t trap_notification_oid_len = OID_LENGTH(trap_notification_oid);

/*
 * notifications with non-standard OID lists
 */

static const uint16_t list_notification_codes[] = {
    0x0002, /* power up */
    0x0020, /* battery voltage low */
    0x001f, /* replace battery */
    0x6300, /* SNMP authentication failure */
    0x0000, /* link up */
    0x0000, /* link down */
    0x0000, /* battery charge start */
    0x0000 /* battery charge stop */
};

static const uint16_t list_device_codes[] = {
    0x0000, /* power up */
    0x0000, /* battery voltage low */
    0x0000, /* replace battery */
    0x0407, /* SNMP authentication failure */
    0x0107, /* link up */
    0x0108, /* link down */
    0x0086, /* battery charge start */
    0x0087 /* battery charge stop */
};

static const SubOID trap_cold_start_oid[] =
    { SNMP_OID_SNMPMODULES, 1, 1, 5, 1 };
static const SubOID trap_battery_low_oid[] =
    { SNMP_OID_BATTERY_MIB, 0, 2 };
static const SubOID trap_battery_aging_oid[] =
    { SNMP_OID_BATTERY_MIB, 0, 5 };
static const SubOID trap_authentication_failure_oid[] =
    { SNMP_OID_SNMPMODULES, 1, 1, 5, 5 };
static const SubOID trap_link_up_oid[] =
    { SNMP_OID_SNMPMODULES, 1, 1, 5, 4 };
static const SubOID trap_link_down_oid[] =
    { SNMP_OID_SNMPMODULES, 1, 1, 5, 3 };
static const SubOID trap_battery_charging_state_oid[] =
    { SNMP_OID_BATTERY_MIB, 0, 1 };

static const SubOID *list_identifier_oid[] = {
    trap_cold_start_oid, /* power up */
    trap_battery_low_oid, /* battery voltage */
    trap_battery_aging_oid, /* replace battery */
    trap_authentication_failure_oid, /* SNMP authentication failure */
    trap_link_up_oid, /* link up */
    trap_link_down_oid, /* link down */
    trap_battery_charging_state_oid, /* battery charge start */
    trap_battery_charging_state_oid /* battery charge stop */
};

static const size_t list_identifier_oid_len[] = {
    OID_LENGTH(trap_cold_start_oid), /* power up */
    OID_LENGTH(trap_battery_low_oid), /* battery voltage */
    OID_LENGTH(trap_battery_aging_oid), /* replace battery */
    OID_LENGTH(trap_authentication_failure_oid), /* SNMP authentication failure */
    OID_LENGTH(trap_link_up_oid), /* link up */
    OID_LENGTH(trap_link_down_oid), /* link down */
    OID_LENGTH(trap_battery_charging_state_oid), /* battery charge start */
    OID_LENGTH(trap_battery_charging_state_oid) /* battery charge stop */
};

/*
 * generic notification arguments
 */
static const SubOID trap_arg_generic_oid[] = { SNMP_OID_ENTERPRISE_MIB, 0, 1, 0 };
static const size_t trap_arg_generic_oid_len = OID_LENGTH(trap_arg_generic_oid);

/* sysUptime.0 */
static const SubOID sys_uptime_oid[] = { SNMP_OID_MIB2, 1, 3 };
static const size_t sys_uptime_oid_len = OID_LENGTH(sys_uptime_oid);

/* maximum amount of generic arguments included in trap varlist */
#define MAX_ARGUMENTS 8

/*
 * non-standard notification arguments
 */

static const SubOID trap_arg_if_index_oid[] = { SNMP_OID_IF_ENTRY_MIB, 1, 0 };
static const size_t trap_arg_if_index_oid_len = OID_LENGTH(trap_arg_if_index_oid);
static const SubOID trap_arg_if_admin_state_oid[] = { SNMP_OID_IF_ENTRY_MIB, 7, 0 };
static const size_t trap_arg_if_admin_state_oid_len =
        OID_LENGTH(trap_arg_if_admin_state_oid);
static const SubOID trap_arg_if_oper_state_oid[] = { SNMP_OID_IF_ENTRY_MIB, 8, 0 };
static const size_t trap_arg_if_oper_state_oid_len =
        OID_LENGTH(trap_arg_if_oper_state_oid);

static const SubOID trap_arg_battery_actual_charge_oid[] =
        { SNMP_OID_BATTERY_MIB, 1, 1, 1, 15, 1 };
static const size_t trap_arg_battery_actual_charge_oid_len =
        OID_LENGTH(trap_arg_battery_actual_charge_oid);
static const SubOID trap_arg_battery_actual_voltage_oid[] =
        { SNMP_OID_BATTERY_MIB, 1, 1, 1, 16, 1 };
static const size_t trap_arg_battery_actual_voltage_oid_len =
        OID_LENGTH(trap_arg_battery_actual_voltage_oid);
static const SubOID trap_arg_battery_cell_identifier_oid[] =
        { SNMP_OID_BATTERY_MIB, 1, 1, 1, 25, 1 };
static const size_t trap_arg_battery_cell_identifier_oid_len =
        OID_LENGTH(trap_arg_battery_cell_identifier_oid);

static const char *default_source = "unknown";

static int add_trap_oid(uint16_t, uint16_t, SnmpScopedPDU *);
static int add_arguments(uint16_t, uint16_t, buf_t *, SnmpScopedPDU *);
static int add_generic_arguments(buf_t *, SnmpScopedPDU *);

int build_authentication_failure_notification(const char *source, buf_t *buf)
{
    asn1int_t version = NOTIFICATION_VERSION;
    uint8_t flags = 0x00;
    asn1int_t device_code = AUTH_FAILURE_DEVICE_CODE;
    asn1int_t notification_code = AUTH_FAILURE_NOTIFICATION_CODE;

    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time); /* continue even if fetching the system time fails */

    int mark = buf->pos;
    if (source == NULL) {
        source = default_source;
    }

    CHECK_ENC_RESULT(encode_OCTET_STRING(buf, (uint8_t *) source, strlen(source)),
            "notification source");
    CHECK_ENC_RESULT(encode_TLV(buf, mark, TAG_SEQUENCE, FLAG_STRUCTURED),
            "notification arguments");
    CHECK_ENC_RESULT(encode_INTEGER(buf, &device_code, TAG_ENUMERATED,
            FLAG_UNIVERSAL), "notification device code");
    CHECK_ENC_RESULT(encode_INTEGER(buf, &notification_code, TAG_ENUMERATED,
        FLAG_UNIVERSAL), "notification code");
    CHECK_ENC_RESULT(encode_UNSIGNED64(buf, (time.tv_sec * 1000) + (time.tv_nsec / 1000000),
        TAG_INTEGER, FLAG_UNIVERSAL), "notification time stamp");
    CHECK_ENC_RESULT(encode_BITSTRING(buf, &flags), "notification flags");
    CHECK_ENC_RESULT(encode_INTEGER(buf, &version, TAG_INTEGER, FLAG_UNIVERSAL),
            "notification version number");
    CHECK_ENC_RESULT(encode_TLV(buf, mark, TAG_SEQUENCE, FLAG_STRUCTURED), "notification");

    return 0;
}

int build_snmp_notification_scoped_pdu(buf_t *source, SnmpScopedPDU *scoped_pdu)
{
    asn1raw_t tlv;
    CHECK_DEC_RESULT(decode_TLV(&tlv, source), "notification sequence parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_SEQUENCE, "wrong notification tag");
    init_ibuf(source, tlv.value, tlv.length);

    /* check version */
    CHECK_DEC_RESULT(decode_TLV(&tlv, source), "notification version parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong version tag");
    asn1int_t version = decode_INTEGER(&tlv);
    if (version != NOTIFICATION_VERSION) {
        syslog(LOG_WARNING, "failed to parse incoming notification : received version %d.",
                (int) version);
        return -1;
    }

    /* skip flags and timestamp */
    CHECK_DEC_RESULT(decode_TLV(&tlv, source), "notification flags parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_BITSTRING, "wrong flags tag");
    CHECK_DEC_RESULT(decode_TLV(&tlv, source), "notification time stamp parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong time stamp tag");

    /* notification code */
    CHECK_DEC_RESULT(decode_TLV(&tlv, source), "notification code parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong notification code tag");
    uint16_t notification_code = decode_INTEGER(&tlv);

    /* device code */
    CHECK_DEC_RESULT(decode_TLV(&tlv, source), "device code parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_INTEGER, "wrong notification code tag");
    uint16_t device_code = decode_INTEGER(&tlv);

    /* arguments */
    CHECK_DEC_RESULT(decode_TLV(&tlv, source), "notification arguments parse exception");
    CHECK_DEC_RESULT(tlv.type != TAG_SEQUENCE, "wrong notification arguments tag");
    init_ibuf(source, tlv.value, tlv.length);

    /* RFC 3416 mandates inclusion of sysUpTime.0 */
    /* NOTE: some notifications are generated retroactively
     * (e.g. offline tamper notifications), in which case this uptime field
     * is not correct. */
    NEW_VAR_BINDING(uptime_binding, scoped_pdu)
    memcpy(uptime_binding->oid.subid, sys_uptime_oid, sizeof(sys_uptime_oid));
    uptime_binding->oid.len = sys_uptime_oid_len;
    uptime_binding->type = SMI_TYPE_TIME_TICKS;
    uptime_binding->value.unsigned_integer = 100 * get_uptime();

    /* snmpTrapOID.0 */
    if (add_trap_oid(notification_code, device_code, scoped_pdu)) {
        syslog(LOG_WARNING, "failed to add trap oid");
        return -1;
    }

    /* additional arguments */
    if (add_arguments(notification_code, device_code, source, scoped_pdu)) {
        syslog(LOG_WARNING, "failed to add trap arguments");
        return -1;
    }

    return 0;
}

static int add_trap_oid(uint16_t notification_code, uint16_t device_code,
        SnmpScopedPDU *scoped_pdu)
{
    NEW_VAR_BINDING(binding, scoped_pdu)

    binding->type = SMI_TYPE_OID;
    binding->oid.len = snmp_trap_oid_len;
    memcpy(binding->oid.subid, snmp_trap_oid, sizeof(snmp_trap_oid));

    /* use non-enterprise OID identifier where possible */
    int i = 0;
    while (i < sizeof(list_notification_codes) / sizeof(uint16_t)) {
        if (list_notification_codes[i] == notification_code &&
                list_device_codes[i] == device_code) {
            memcpy(binding->value.oid.subid, list_identifier_oid[i],
                    list_identifier_oid_len[i] * sizeof(SubOID));
            binding->value.oid.len = list_identifier_oid_len[i];
            break;
        }
        i++;
    }
    if (i >= sizeof(list_notification_codes) / sizeof(uint16_t)) {
        /* generic enterprise OID consists of
         * <trap_notification_oid>.<notification_code>.<device_code> */
        memcpy(binding->value.oid.subid, trap_notification_oid,
                sizeof(trap_notification_oid));
        binding->value.oid.len = trap_notification_oid_len;
        binding->value.oid.subid[binding->value.oid.len++] = notification_code;
        binding->value.oid.subid[binding->value.oid.len++] = device_code;
    }

    return 0;
}

static int add_arguments(const uint16_t notification_code,
        const uint16_t device_code, buf_t *buf, SnmpScopedPDU *scoped_pdu)
{
    if (notification_code == list_notification_codes[0]
       && device_code == list_device_codes[0]) { /* power up */
        /* no additional arguments */
    } else if (notification_code == list_notification_codes[1]
            && device_code == list_device_codes[1]) { /* battery voltage low */
        NEW_VAR_BINDING(actual_charge, scoped_pdu)
        memcpy(actual_charge->oid.subid, trap_arg_battery_actual_charge_oid,
            sizeof(trap_arg_battery_actual_charge_oid));
        actual_charge->oid.len = trap_arg_battery_actual_charge_oid_len;
        actual_charge->type = SMI_TYPE_GAUGE_32;
        actual_charge->value.unsigned_integer = 0xffffffff;

        NEW_VAR_BINDING(actual_voltage, scoped_pdu)
        memcpy(actual_voltage->oid.subid, trap_arg_battery_actual_voltage_oid,
            sizeof(trap_arg_battery_actual_voltage_oid));
        actual_voltage->oid.len = trap_arg_battery_actual_voltage_oid_len;
        actual_voltage->type = SMI_TYPE_GAUGE_32;
        actual_voltage->value.unsigned_integer = 0xffffffff;

        NEW_VAR_BINDING(battery_cell_identifier, scoped_pdu)
        memcpy(battery_cell_identifier->oid.subid,
            trap_arg_battery_cell_identifier_oid,
            sizeof(trap_arg_battery_cell_identifier_oid));
        battery_cell_identifier->oid.len = trap_arg_battery_cell_identifier_oid_len;
        battery_cell_identifier->type = SMI_TYPE_OCTET_STRING;
        battery_cell_identifier->value.octet_string.len = 0;
    } else if (notification_code == list_notification_codes[4]
            && (device_code == list_device_codes[4]
            || device_code == list_device_codes[5])) { /* link up/down */
        /* ifIndex */
        /* TODO: convert interface name to index (index might change after
         * agent restart, while name is fixed) */
        asn1raw_t tlv;
        CHECK_DEC_RESULT(decode_TLV(&tlv, buf), "notification interface name parse exception");
        CHECK_DEC_RESULT(tlv.type != TAG_OCTETSTRING, "wrong interface name tag");
        NEW_VAR_BINDING(if_index, scoped_pdu);
        memcpy(if_index->oid.subid, trap_arg_if_index_oid, sizeof(trap_arg_if_index_oid));
        if_index->oid.len = trap_arg_if_index_oid_len;
        if_index->type = SMI_TYPE_OCTET_STRING;
        if_index->value.octet_string.octets = tlv.value;
        if_index->value.octet_string.len = tlv.length;

        /* ifAdminStatus */
        NEW_VAR_BINDING(if_admin_status, scoped_pdu)
        memcpy(if_admin_status->oid.subid, trap_arg_if_admin_state_oid,
                sizeof(trap_arg_if_admin_state_oid));
        if_admin_status->oid.len = trap_arg_if_admin_state_oid_len;
        if_admin_status->type = SMI_TYPE_INTEGER_32;
        if_admin_status->value.integer = (device_code == list_device_codes[4]) ? 1 : 2;

        /* ifOperStatus */
        NEW_VAR_BINDING(if_oper_status, scoped_pdu)
        memcpy(if_oper_status->oid.subid, trap_arg_if_oper_state_oid,
                sizeof(trap_arg_if_oper_state_oid));
        if_oper_status->oid.len = trap_arg_if_oper_state_oid_len;
        if_oper_status->type = SMI_TYPE_INTEGER_32;
        if_oper_status->value.integer = (device_code == list_device_codes[4]) ? 1 : 2;
    } else if (notification_code == list_notification_codes[6]
            && (device_code == list_device_codes[6]
            || device_code == list_device_codes[7])) { /* battery charge start/stop */
        /* batteryChargingOperState charging(2)/maintainingCharge(3) */
        NEW_VAR_BINDING(battery_charging_state, scoped_pdu)
        memcpy(battery_charging_state->oid.subid, trap_arg_if_admin_state_oid,
                sizeof(trap_arg_if_admin_state_oid));
        battery_charging_state->oid.len = trap_arg_if_admin_state_oid_len;
        battery_charging_state->type = SMI_TYPE_INTEGER_32;
        battery_charging_state->value.integer =
                (device_code == list_device_codes[6]) ? 2 : 3;
    } else {
        return add_generic_arguments(buf, scoped_pdu);
    }

    return 0;
}

static int add_generic_arguments(buf_t *buf, SnmpScopedPDU *scoped_pdu)
{
    SubOID argument_oid[MAX_OID_LEN];
    memcpy(argument_oid, trap_arg_generic_oid, sizeof(trap_arg_generic_oid));
    size_t argument_oid_len = trap_arg_generic_oid_len + 1;

    for (int i = 0; i < MAX_ARGUMENTS && buf->pos < buf->size; i++) {
        asn1raw_t tlv;
        CHECK_DEC_RESULT(decode_TLV(&tlv, buf), "notification argument parse exception");
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

            case TAG_OCTETSTRING: {
                var_binding->type = SMI_TYPE_OCTET_STRING;
                var_binding->value.octet_string.octets = tlv.value;
                var_binding->value.octet_string.len = tlv.length;
                break;
            }

            default: {
                syslog(LOG_WARNING, "unexpected notification argument type %02x",
                    tlv.type);
            }
        }
    }

    return 0;
}
