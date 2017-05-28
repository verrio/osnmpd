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
#include "snmp-mib/ip/ip-traps.h"

#define SNMP_OID_IF_ENTRY_MIB   1,3,6,1,2,1,2,2,1

static int add_link_up_down_arguments(const agent_notification *,
    buf_t *, SnmpScopedPDU *);

static const SubOID trap_link_up_oid[] = { SNMP_OID_SNMPMODULES, 1, 1, 5, 4 };
static const SubOID trap_link_down_oid[] = { SNMP_OID_SNMPMODULES, 1, 1, 5, 3 };
static const SubOID trap_arg_if_index_oid[] = { SNMP_OID_IF_ENTRY_MIB, 1, 0 };
static const size_t trap_arg_if_index_oid_len = OID_LENGTH(trap_arg_if_index_oid);
static const SubOID trap_arg_if_admin_state_oid[] = { SNMP_OID_IF_ENTRY_MIB, 7, 0 };
static const size_t trap_arg_if_admin_state_oid_len =
    OID_LENGTH(trap_arg_if_admin_state_oid);
static const SubOID trap_arg_if_oper_state_oid[] = { SNMP_OID_IF_ENTRY_MIB, 8, 0 };
static const size_t trap_arg_if_oper_state_oid_len =
    OID_LENGTH(trap_arg_if_oper_state_oid);

agent_notification trap_link_up = {
    .code_1 = 0x0000,
    .code_2 = 0x0107,
    .oid = trap_link_up_oid,
    .oid_len = OID_LENGTH(trap_link_up_oid),
    .add_arguments = add_link_up_down_arguments
};

agent_notification trap_link_down = {
    .code_1 = 0x0000,
    .code_2 = 0x0108,
    .oid = trap_link_down_oid,
    .oid_len = OID_LENGTH(trap_link_down_oid),
    .add_arguments = add_link_up_down_arguments
};

static int add_link_up_down_arguments(const agent_notification *notification,
        buf_t *buf, SnmpScopedPDU *scoped_pdu)
{
    /* ifIndex */
    /* TODO: convert interface name to index (index might change after
     * agent restart, while name is fixed) */
    asn1raw_t tlv;
    CHECK_TRAP_DEC_RESULT(decode_TLV(&tlv, buf),
            "notification interface name parse exception");
    CHECK_TRAP_DEC_RESULT(tlv.type != TAG_OCTETSTRING, "wrong interface name tag");
    NEW_VAR_BINDING(if_index, scoped_pdu);
    memcpy(if_index->oid.subid, trap_arg_if_index_oid, sizeof(trap_arg_if_index_oid));
    if_index->oid.len = trap_arg_if_index_oid_len;
    if_index->type = SMI_TYPE_OCTET_STRING;
    if_index->value.octet_string.octets = tlv.value;
    if_index->value.octet_string.len = tlv.length;

    int is_up = (notification->code_2 == trap_link_up.code_2) ? 1 : 2;

    /* ifAdminStatus */
    NEW_VAR_BINDING(if_admin_status, scoped_pdu)
    memcpy(if_admin_status->oid.subid, trap_arg_if_admin_state_oid,
            sizeof(trap_arg_if_admin_state_oid));
    if_admin_status->oid.len = trap_arg_if_admin_state_oid_len;
    if_admin_status->type = SMI_TYPE_INTEGER_32;
    if_admin_status->value.integer = is_up;

    /* ifOperStatus */
    NEW_VAR_BINDING(if_oper_status, scoped_pdu)
    memcpy(if_oper_status->oid.subid, trap_arg_if_oper_state_oid,
            sizeof(trap_arg_if_oper_state_oid));
    if_oper_status->oid.len = trap_arg_if_oper_state_oid_len;
    if_oper_status->type = SMI_TYPE_INTEGER_32;
    if_oper_status->value.integer = is_up;

    return 0;
}
