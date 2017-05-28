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

#include "snmp-agent/mib-tree.h"
#include "snmp-mib/power/battery-traps.h"

static int add_battery_low_arguments(const agent_notification *,
    buf_t *, SnmpScopedPDU *);
static int add_battery_charge_arguments(const agent_notification *,
    buf_t *, SnmpScopedPDU *);

static const SubOID trap_battery_low_oid[] = { SNMP_OID_BATTERY_MIB, 0, 2 };
static const SubOID trap_battery_aging_oid[] = { SNMP_OID_BATTERY_MIB, 0, 5 };
static const SubOID trap_battery_charging_state_oid[] =
    { SNMP_OID_BATTERY_MIB, 0, 1 };
static const SubOID trap_arg_battery_oper_state_oid[] =
    { SNMP_OID_BATTERY_MIB, 1, 1, 1, 13, 1 };
static const SubOID trap_arg_battery_actual_charge_oid[] =
    { SNMP_OID_BATTERY_MIB, 1, 1, 1, 15, 1 };
static const SubOID trap_arg_battery_actual_voltage_oid[] =
    { SNMP_OID_BATTERY_MIB, 1, 1, 1, 16, 1 };
static const SubOID trap_arg_battery_cell_identifier_oid[] =
    { SNMP_OID_BATTERY_MIB, 1, 1, 1, 25, 1 };

agent_notification battery_low_voltage = {
    .code_1 = 0x0020,
    .code_2 = 0x0000,
    .oid = trap_battery_low_oid,
    .oid_len = OID_LENGTH(trap_battery_low_oid),
    .add_arguments = add_battery_low_arguments
};

agent_notification battery_replace = {
    .code_1 = 0x001f,
    .code_2 = 0x0000,
    .oid = trap_battery_aging_oid,
    .oid_len = OID_LENGTH(trap_battery_aging_oid),
    .add_arguments = NULL
};

agent_notification battery_charge_start = {
    .code_1 = 0x0000,
    .code_2 = 0x0086,
    .oid = trap_battery_charging_state_oid,
    .oid_len = OID_LENGTH(trap_battery_charging_state_oid),
    .add_arguments = add_battery_charge_arguments
};

agent_notification battery_charge_stop = {
    .code_1 = 0x0000,
    .code_2 = 0x0087,
    .oid = trap_battery_charging_state_oid,
    .oid_len = OID_LENGTH(trap_battery_charging_state_oid),
    .add_arguments = add_battery_charge_arguments
};

static int add_battery_low_arguments(const agent_notification *notification,
        buf_t *buf, SnmpScopedPDU *scoped_pdu)
{
    NEW_VAR_BINDING(actual_charge, scoped_pdu)
    memcpy(actual_charge->oid.subid, trap_arg_battery_actual_charge_oid,
        sizeof(trap_arg_battery_actual_charge_oid));
    actual_charge->oid.len = OID_LENGTH(trap_arg_battery_actual_charge_oid);
    actual_charge->type = SMI_TYPE_GAUGE_32;
    actual_charge->value.unsigned_integer = 0xffffffff;

    NEW_VAR_BINDING(actual_voltage, scoped_pdu)
    memcpy(actual_voltage->oid.subid, trap_arg_battery_actual_voltage_oid,
        sizeof(trap_arg_battery_actual_voltage_oid));
    actual_voltage->oid.len = OID_LENGTH(trap_arg_battery_actual_voltage_oid);
    actual_voltage->type = SMI_TYPE_GAUGE_32;
    actual_voltage->value.unsigned_integer = 0xffffffff;

    NEW_VAR_BINDING(battery_cell_identifier, scoped_pdu)
    memcpy(battery_cell_identifier->oid.subid,
        trap_arg_battery_cell_identifier_oid,
        sizeof(trap_arg_battery_cell_identifier_oid));
    battery_cell_identifier->oid.len = OID_LENGTH(trap_arg_battery_cell_identifier_oid);
    battery_cell_identifier->type = SMI_TYPE_OCTET_STRING;
    battery_cell_identifier->value.octet_string.len = 0;

    return 0;
}

static int add_battery_charge_arguments(const agent_notification *notification,
        buf_t *buf, SnmpScopedPDU *scoped_pdu)
{
    /* batteryChargingOperState charging(2)/maintainingCharge(3) */
    NEW_VAR_BINDING(battery_charging_state, scoped_pdu)
    memcpy(battery_charging_state->oid.subid, trap_arg_battery_oper_state_oid,
            sizeof(trap_arg_battery_oper_state_oid));
    battery_charging_state->oid.len = OID_LENGTH(trap_arg_battery_oper_state_oid);
    battery_charging_state->type = SMI_TYPE_INTEGER_32;
    battery_charging_state->value.integer =
            (notification->code_2 == battery_charge_start.code_2) ? 2 : 3;

    return 0;
}
