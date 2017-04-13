/*
 * This file is part of the osnmpd project (http://osnmpd.github.io).
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

#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/route.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <inttypes.h>
#include <netdb.h>

#include "config.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-incoming.h"
#include "snmp-agent/agent-notification.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/snmp-crypto.h"
#include "snmp-core/utils.h"

/* size required for control data */
#define CONTROL_DATASIZE (CMSG_SPACE(sizeof(struct in6_pktinfo)))

/* multicast groups */
#define IP4_GROUP "224.0.0.1"
#define IP6_GROUP "ff02::1"

struct in6_pktinfo {
    struct in6_addr ipi6_addr; /* src/dst IPv6 address */
    unsigned int ipi6_ifindex; /* send/recv interface index */
};

/* OID prefix for public accessible subtree */
static SubOID public_prefix[] = { SNMP_OID_SYSTEM_MIB };

/* get-bulk limits */
#define MAX_REPEAT 0x40

/* USM security context */
static int user_enabled[NUMBER_OF_USER_SLOTS];
static SnmpUSMContext usm_context[NUMBER_OF_USER_SLOTS];

/* agent engine ID */
static uint8_t *engine_id;
static size_t engine_id_len;

/* UDP socket */
static int udp_socket_descriptor = -1;

static int init_socket(struct pollfd *);
static int init_usm_context(void);
static int allowed_interface(unsigned int);
static int validate_pdu_header(SnmpPDU *, SnmpUserSlot *);
static int is_authenticated_get(SnmpUserSlot, OID *);
static int is_authenticated_set(SnmpUserSlot, OID *);
static int is_discovery_request(SnmpPDU *, SnmpScopedPDU *);
static int is_time_sync_request(SnmpPDU *);
static int handle_decoded_request(SnmpPDU *, buf_t *, int *);
static int handle_scoped_pdu(SnmpUserSlot, SnmpPDU *, SnmpScopedPDU *, buf_t *, int);
static int handle_get_request(SnmpUserSlot, SnmpPDU *, SnmpScopedPDU *, buf_t *,
        int, int, int, int);
static int handle_set_request(SnmpUserSlot, SnmpPDU *, SnmpScopedPDU *, buf_t *, int);
static int generate_discovery_response(SnmpPDU *, SnmpScopedPDU *, buf_t *);
static int generate_time_sync_response(SnmpUserSlot, SnmpPDU *, SnmpScopedPDU *, buf_t *);
static int generate_security_error_response(SnmpUserSlot, SnmpPDU *, buf_t *, int, int *);
static int generate_error_response(SnmpUserSlot, SnmpPduType, SnmpErrorStatus, int,
        SnmpPDU *, SnmpScopedPDU *, buf_t *);
static int build_response_pdu(SnmpUserSlot, SnmpPDU *, buf_t *, int);
static void fill_security_header(SnmpPDU *);
static void fill_context_header(SnmpScopedPDU *);
static void release_bindings(SnmpScopedPDU *);
static void increment_incoming_pdu_counter(SnmpScopedPDU *);
static void increment_incoming_error_counter(SnmpScopedPDU *);

/* initialise agent */
int init_incoming_handler(struct pollfd *poll_descriptor)
{
    if (init_socket(poll_descriptor)) {
        return -1;
    } else if (init_usm_context()) {
        syslog(LOG_ERR, "failed to initialise user context");
        return -1;
    }

    return 0;
}

/* finish UDP socket */
int finish_incoming_handler(void)
{
    if (udp_socket_descriptor != -1 && close(udp_socket_descriptor) == -1) {
        syslog(LOG_ERR, "failed to close socket : %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* handle incoming SNMP request */
void handle_request(void)
{
    uint8_t rx_buf[MAX_PDU_SIZE];
    uint8_t tx_buf[MAX_PDU_SIZE];
    struct iovec iov[1];
    iov[0].iov_base = rx_buf;
    iov[0].iov_len = sizeof(rx_buf);
    uint8_t cmsg[CONTROL_DATASIZE];

    struct msghdr message;
    struct sockaddr_storage src_addr;
    message.msg_name = &src_addr;
    message.msg_namelen = sizeof(src_addr);
    message.msg_control = &cmsg;
    message.msg_controllen = sizeof(cmsg);
    message.msg_iov = iov;
    message.msg_iovlen = 1;

    ssize_t rx_size = recvmsg(udp_socket_descriptor, &message, 0);
    if (rx_size < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            syslog(LOG_WARNING, "failed to receive incoming SNMP request : %s", strerror(errno));
        }
        return;
    }

    get_statistics()->snmp_in_pkts++;

    if (get_agent_interfaces() != NULL) {
        int iface = -1;
        for (struct cmsghdr *cmsgptr = CMSG_FIRSTHDR(&message); cmsgptr != NULL;
                cmsgptr = CMSG_NXTHDR(&message, cmsgptr)) {
            if (cmsgptr->cmsg_level == IPPROTO_IPV6 && cmsgptr->cmsg_type == IPV6_PKTINFO) {
                struct in6_pktinfo *pktinfo = (struct in6_pktinfo *) (CMSG_DATA(cmsgptr));
                iface = pktinfo->ipi6_ifindex;
                break;
            }
        }
        if (iface <= 0 || allowed_interface(iface)) {
            syslog(LOG_DEBUG, "incoming request on invalid interface %i", iface);
            get_statistics()->snmp_silent_drops++;
            return;
        }
    }

    buf_t buf;
    asn1raw_t pdu_tlv;
    init_ibuf(&buf, rx_buf, rx_size);
    if (decode_TLV(&pdu_tlv, &buf)) {
        syslog(LOG_WARNING, "incoming request is not a BER TLV");
        get_statistics()->snmp_in_asn_parse_errs++;
        get_statistics()->snmp_silent_drops++;
        return;
    }

    SnmpPDU pdu;
    int parse_result = decode_snmp_pdu(&pdu_tlv, &pdu);
    switch (parse_result) {
        case PARSE_SUCCESS: {
            break;
        }

        case PARSE_ERROR_VERSION: {
            syslog(LOG_WARNING, "incoming request has unsupported version");
            get_statistics()->snmp_in_bad_versions++;
            get_statistics()->snmp_silent_drops++;
            return;
        }

        case PARSE_ERROR_SEC_MODEL: {
            syslog(LOG_WARNING, "incoming request has unsupported security model");
            get_statistics()->snmp_unknown_security_models++;
            get_statistics()->snmp_silent_drops++;
            return;
        }

        default: {
            syslog(LOG_WARNING, "failed to decode incoming request");
            get_statistics()->snmp_in_asn_parse_errs++;
            get_statistics()->snmp_silent_drops++;
            return;
        }
    }

    if (!pdu.requires_response) {
        syslog(LOG_DEBUG, "incoming request does not require response");
        return;
    }

    buf_t output_buf;
    int auth_trap = 0;
    init_obuf(&output_buf, tx_buf, sizeof(tx_buf));
    if (handle_decoded_request(&pdu, &output_buf, &auth_trap)) {
        get_statistics()->snmp_silent_drops++;
        return;
    }

    if (auth_trap) {
        char req_source[256];
        int result = getnameinfo(message.msg_name, message.msg_namelen,
                req_source, sizeof(req_source), NULL, 0, NI_NUMERICHOST);
        dispatch_auth_failed_notification(result ? "N/A" : req_source);
    }

    iov[0].iov_base = &output_buf.buffer[output_buf.pos];
    iov[0].iov_len = output_buf.size - output_buf.pos;
    if (sendmsg(udp_socket_descriptor, &message, 0) == -1) {
        syslog(LOG_WARNING, "failed to dispatch response PDU : %s", strerror(errno));
        return;
    }

    get_statistics()->snmp_out_pkts++;
}

static int allowed_interface(unsigned int iface)
{
    char iface_name[IFNAMSIZ];
    if (if_indextoname(iface, iface_name) == NULL) {
        return 1;
    }

    for (char **p = get_agent_interfaces(); *p != NULL; p++) {
        if (!strcmp(iface_name, *p)) {
            return 0;
        }
    }

    return 1;
}

static int handle_decoded_request(SnmpPDU *pdu, buf_t *output_buf,
        int *auth_trap)
{
    SnmpScopedPDU scoped_pdu;
    SnmpUserSlot user = -1;
    int user_found;
    int sec_result;

    if (!pdu->is_authenticated && pdu->is_encrypted) {
        syslog(LOG_WARNING, "encryption without authentication not allowed");
        /* seems to be the only case where incrementing the counter is allowed by RFC 3412 */
        get_statistics()->snmp_invalid_msgs++;
        return generate_error_response(user, REPORT, GENERAL_ERROR, 0, pdu, NULL, output_buf);
    } else if (is_discovery_request(pdu, &scoped_pdu)) {
        increment_incoming_pdu_counter(&scoped_pdu);
        return generate_discovery_response(pdu, &scoped_pdu, output_buf);
    } else if ((user_found = validate_pdu_header(pdu, &user))) {
        return generate_error_response(user, RESPONSE,
                user_found == -2 ? NO_SUCH_NAME : GENERAL_ERROR, 0, pdu, NULL,
                output_buf);
    } else if (is_time_sync_request(pdu)) {
        if ((sec_result = process_incoming_pdu(pdu, &scoped_pdu,
                &usm_context[user], 1)) == PROCESSING_NO_ERROR) {
            increment_incoming_pdu_counter(&scoped_pdu);
            return generate_time_sync_response(user, pdu, &scoped_pdu, output_buf);
        } else {
            return generate_security_error_response(user, pdu, output_buf,
                sec_result, auth_trap);
        }
    } else if ((sec_result = process_incoming_pdu(pdu, &scoped_pdu,
            &usm_context[user], 0)) != PROCESSING_NO_ERROR) {
        return generate_security_error_response(user, pdu, output_buf, sec_result, auth_trap);
    }

    increment_incoming_pdu_counter(&scoped_pdu);
    int max_size = min(MAX_PDU_SIZE, pdu->max_size);
    pdu->scoped_pdu.decrypted_pdu = &scoped_pdu;
    pdu->max_size = MAX_PDU_SIZE;
    pdu->requires_response = 0;
    fill_security_header(pdu);

    return handle_scoped_pdu(user, pdu, &scoped_pdu, output_buf, max_size);
}

static int validate_pdu_header(SnmpPDU *pdu, SnmpUserSlot *user)
{
    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);
    if (engine_id_len != pdu->security_parameters.authoritative_engine_id_len
        || memcmp(engine_id, pdu->security_parameters.authoritative_engine_id, engine_id_len)) {
        char engine_id_hex[3 + (MAX_ENGINE_ID_LENGTH << 1)];
        if (to_hex(pdu->security_parameters.authoritative_engine_id,
                pdu->security_parameters.authoritative_engine_id_len,
                engine_id_hex, sizeof(engine_id_hex))) {
            syslog(LOG_WARNING, "received request for unknown engine %s", engine_id_hex);
        }
        get_statistics()->usm_stats_unknown_engine_ids++;
        return -1;
    }

    for (int i = 0; i < NUMBER_OF_USER_SLOTS; i++) {
        if (!user_enabled[i]) {
            continue;
        } else if (usm_context[i].user_name_len != strlen(pdu->security_parameters.user_name)) {
            continue;
        } else if (memcmp(usm_context[i].user_name, pdu->security_parameters.user_name,
                usm_context[i].user_name_len)) {
            continue;
        } else {
            *user = i;
            return 0;
        }
    }

    syslog(LOG_WARNING, "received request for unknown user %s",
            pdu->security_parameters.user_name);
    get_statistics()->usm_stats_unknown_user_names++;

    return -2;
}

static int handle_scoped_pdu(SnmpUserSlot user, SnmpPDU *pdu,
        SnmpScopedPDU *scoped_pdu, buf_t *output_buf, int max_size)
{
    uint8_t *engine_id;
    size_t engine_id_len = get_engine_id(&engine_id);
    if (engine_id_len != scoped_pdu->context_engine_id_len
            || memcmp(engine_id, scoped_pdu->context_engine_id, engine_id_len)) {
        char engine_id_hex[3 + (MAX_ENGINE_ID_LENGTH << 1)];
        if (to_hex(scoped_pdu->context_engine_id, scoped_pdu->context_engine_id_len,
                engine_id_hex, sizeof(engine_id_hex))) {
            syslog(LOG_WARNING, "received request for unknown PDU handler %s", engine_id_hex);
        }
        get_statistics()->snmp_unknown_pdu_handlers++;
        return generate_error_response(user, RESPONSE,
            GENERAL_ERROR, 0, pdu, scoped_pdu, output_buf);
    }

    /* accept all context names, since not all clients
     * allow this parameter to be configured. */

    increment_incoming_error_counter(scoped_pdu);
    switch (scoped_pdu->type) {
        case GET: {
            if (scoped_pdu->error_status != NO_ERROR || scoped_pdu->error_index != 0) {
                return generate_error_response(user, RESPONSE, GENERAL_ERROR, 0,
                        pdu, scoped_pdu, output_buf);
            }

            return handle_get_request(user, pdu, scoped_pdu, output_buf, max_size,
                    0, 0, 1);
        }

        case GET_NEXT: {
            if (scoped_pdu->error_status != NO_ERROR || scoped_pdu->error_index != 0) {
                return generate_error_response(user, RESPONSE, GENERAL_ERROR, 0,
                        pdu, scoped_pdu, output_buf);
            }

            return handle_get_request(user, pdu, scoped_pdu, output_buf, max_size,
                    1, 0, 1);
        }

        case GET_BULK: {
            if (scoped_pdu->non_repeaters > scoped_pdu->num_of_bindings
                    || scoped_pdu->max_repetitions > MAX_REPEAT) {
                return generate_error_response(user, RESPONSE, GENERAL_ERROR, 0,
                        pdu, scoped_pdu, output_buf);
            }

            return handle_get_request(user, pdu, scoped_pdu, output_buf, max_size,
                    1, scoped_pdu->non_repeaters, scoped_pdu->max_repetitions);
        }

        case SET: {
            if (scoped_pdu->error_status != NO_ERROR || scoped_pdu->error_index != 0) {
                return generate_error_response(user, RESPONSE, GENERAL_ERROR, 0,
                        pdu, scoped_pdu, output_buf);
            }

            return handle_set_request(user, pdu, scoped_pdu, output_buf, max_size);
        }

        default: {
            return generate_error_response(user, RESPONSE, GENERAL_ERROR, 0, pdu,
                    scoped_pdu, output_buf);
        }
    }
}

static int handle_get_request(SnmpUserSlot user, SnmpPDU *pdu,
        SnmpScopedPDU *scoped_pdu, buf_t *output_buf, int max_size, int next,
        int offset, int limit)
{
    SnmpScopedPDU response_scoped_pdu;
    fill_context_header(&response_scoped_pdu);
    response_scoped_pdu.request_id = scoped_pdu->request_id;
    response_scoped_pdu.type = RESPONSE;
    response_scoped_pdu.error_status = NO_ERROR;
    response_scoped_pdu.error_index = 0;
    response_scoped_pdu.num_of_bindings = 0;

    for (int i = 0; i < scoped_pdu->num_of_bindings; i++) {
        if (scoped_pdu->bindings[i].type != SMI_TYPE_NULL) {
            get_statistics()->snmp_in_bad_values++;
            get_statistics()->snmp_out_get_responses++;
            release_bindings(&response_scoped_pdu);
            return generate_error_response(user, RESPONSE, GENERAL_ERROR, i + 1,
                    pdu, scoped_pdu, output_buf);
        }

        int max_repeat = i < offset ? 1 : limit;

        SnmpVariableBinding *previous_binding = NULL;

        for (int j = 0; j < max_repeat; j++) {
            SnmpVariableBinding *binding =
                add_variable_binding(&response_scoped_pdu);

            if (binding == NULL) {
                get_statistics()->snmp_out_get_responses++;
                release_bindings(&response_scoped_pdu);
                return generate_error_response(user, RESPONSE, TOO_BIG, i + 1,
                        pdu, scoped_pdu, output_buf);
            }

            if (previous_binding != NULL) {
                memcpy(&binding->oid, &previous_binding->oid, sizeof(OID));
            } else {
                memcpy(&binding->oid, &scoped_pdu->bindings[i].oid,
                        sizeof(OID));
            }
            binding->type = SMI_TYPE_NULL;
            SnmpErrorStatus status = next ?
                mib_get_next_entry(binding) : mib_get_entry(binding);

            if (status != NO_ERROR) {
                get_statistics()->snmp_out_get_responses++;
                release_bindings(&response_scoped_pdu);
                return generate_error_response(user, RESPONSE, status, i + 1,
                        pdu, scoped_pdu, output_buf);
            } else if (is_authenticated_get(user, &binding->oid)) {
                get_statistics()->snmp_in_bad_community_uses++;
                get_statistics()->snmp_out_get_responses++;
                release_bindings(&response_scoped_pdu);
                return generate_error_response(user, RESPONSE, GENERAL_ERROR,
                        i + 1, pdu, scoped_pdu, output_buf);
            }

            if (binding->type & 0x80) {
                /* no need to repeat further */
                break;
            }

            previous_binding = binding;
        }

        get_statistics()->snmp_in_total_req_vars++;
    }

    get_statistics()->snmp_out_get_responses++;
    pdu->scoped_pdu.decrypted_pdu = &response_scoped_pdu;
    size_t orig_num_bindings = response_scoped_pdu.num_of_bindings;
    int ret = build_response_pdu(user, pdu, output_buf, max_size);
    size_t new_num_bindings = response_scoped_pdu.num_of_bindings;
    response_scoped_pdu.num_of_bindings = orig_num_bindings;
    release_bindings(&response_scoped_pdu);
    if (response_scoped_pdu.error_status == TOO_BIG && limit == 1) {
        return generate_error_response(user, RESPONSE, TOO_BIG, new_num_bindings,
            pdu, scoped_pdu, output_buf);
    }
    return ret;
}

static int handle_set_request(SnmpUserSlot user, SnmpPDU *pdu,
        SnmpScopedPDU *scoped_pdu, buf_t *output_buf, int max_size)
{
    fill_context_header(scoped_pdu);
    scoped_pdu->type = RESPONSE;

    /* step 1: validate all variables */
    for (int i = 0; i < scoped_pdu->num_of_bindings; i++) {
        if (is_authenticated_set(user, &scoped_pdu->bindings[i].oid)) {
            get_statistics()->snmp_in_bad_community_uses++;
            get_statistics()->snmp_out_get_responses++;
            return generate_error_response(user, RESPONSE, NO_ACCESS, i + 1, pdu,
                    scoped_pdu, output_buf);
        }

        SnmpErrorStatus status = mib_set_entry(&scoped_pdu->bindings[i], 1);
        if (status != NO_ERROR) {
            get_statistics()->snmp_out_get_responses++;
            return generate_error_response(user, RESPONSE, status, i + 1, pdu,
                    scoped_pdu, output_buf);
        }
    }

    /* step 2: execute request (no rollback) */
    for (int i = 0; i < scoped_pdu->num_of_bindings; i++) {
        SnmpErrorStatus status = mib_set_entry(&scoped_pdu->bindings[i], 0);
        if (status != NO_ERROR) {
            syslog(LOG_WARNING, "failed to execute set : return code %u", status);
            get_statistics()->snmp_out_get_responses++;
            return generate_error_response(user, RESPONSE, UNDO_FAILED, i + 1,
                    pdu, scoped_pdu, output_buf);
        }
    }

    get_statistics()->snmp_out_get_responses++;
    return build_response_pdu(user, pdu, output_buf, max_size);
}

static void release_bindings(SnmpScopedPDU *scoped_pdu)
{
    for (int i = 0; i < scoped_pdu->num_of_bindings; i++) {
        if ((scoped_pdu->bindings[i].type == SMI_TYPE_OCTET_STRING
                || scoped_pdu->bindings[i].type == SMI_TYPE_OPAQUE)) {
            free(scoped_pdu->bindings[i].value.octet_string.octets);
        }
    }
}

static int is_authenticated_get(SnmpUserSlot user, OID *oid)
{
    //TODO provide fine-grained access control
    if (user == USER_PUBLIC) {
        if (oid->len < OID_LENGTH(public_prefix)) {
            return -1;
        } else if (memcmp(public_prefix, oid->subid,
        OID_LENGTH(public_prefix) * sizeof(SubOID))) {
            return -1;
        }
    }

    return 0;
}

static int is_authenticated_set(SnmpUserSlot user, OID *oid)
{
    //TODO provide fine-grained access control
    if (user == USER_READ_WRITE || user == USER_ADMIN) {
        return 0;
    }

    return -1;
}

static int is_discovery_request(SnmpPDU *pdu, SnmpScopedPDU *scoped_pdu)
{
    /* engineID should be empty */
    if (pdu->security_parameters.authoritative_engine_id_len > 0) {
        return 0;
    }

    /* no security nor authentication */
    if (pdu->is_authenticated || pdu->is_encrypted) {
        return 0;
    }

    /* username should normally be empty, but some clients seem to fill this
     * with fixed string (e.g. Zoho MIBBrowser).  Skip check. */

    /* should be a read class */
    buf_t buf;
    init_ibuf(&buf, pdu->scoped_pdu.encrypted_pdu.data,
            pdu->scoped_pdu.encrypted_pdu.len);
    asn1raw_t payload;
    if (decode_TLV(&payload, &buf) || decode_snmp_scoped_pdu(&payload, scoped_pdu)) {
        syslog(LOG_WARNING, "unencrypted request with invalid scoped PDU");
        get_statistics()->snmp_invalid_msgs++;
        return 0;
    } else if (scoped_pdu->type != GET && scoped_pdu->type != GET_NEXT
            && scoped_pdu->type != GET_BULK) {
        return 0;
    }

    return 1;
}

static int is_time_sync_request(SnmpPDU *pdu)
{
    if (!pdu->is_authenticated) {
        return 0;
    } else if (pdu->security_parameters.authoritative_engine_boots != 0) {
        return 0;
    } else if (pdu->security_parameters.authoritative_engine_time != 0) {
        return 0;
    }

    return 1;
}

static int generate_discovery_response(SnmpPDU *pdu, SnmpScopedPDU *scoped_pdu,
        buf_t *output_buf)
{
    int max_pdu_size = min(pdu->max_size, MAX_PDU_SIZE);

    pdu->scoped_pdu.decrypted_pdu = scoped_pdu;
    pdu->max_size = MAX_PDU_SIZE;
    pdu->requires_response = 0;
    fill_security_header(pdu);
    fill_context_header(scoped_pdu);
    scoped_pdu->type = REPORT;
    scoped_pdu->error_status = NO_ERROR;
    scoped_pdu->error_index = 0;
    scoped_pdu->num_of_bindings = 1;
    SET_OID(scoped_pdu->bindings[0].oid, SNMP_OID_UNKNOWN_ENGINE_ID_COUNTER);
    scoped_pdu->bindings[0].type = SMI_TYPE_COUNTER_32;
    scoped_pdu->bindings[0].value.unsigned_integer =
            get_statistics()->usm_stats_unknown_engine_ids;

    return build_response_pdu(-1, pdu, output_buf, max_pdu_size);
}

static int generate_time_sync_response(SnmpUserSlot user, SnmpPDU *pdu,
        SnmpScopedPDU *scoped_pdu, buf_t *output_buf)
{
    int max_pdu_size = min(pdu->max_size, MAX_PDU_SIZE);

    pdu->scoped_pdu.decrypted_pdu = scoped_pdu;
    pdu->max_size = MAX_PDU_SIZE;
    pdu->requires_response = 0;
    fill_security_header(pdu);
    fill_context_header(scoped_pdu);
    scoped_pdu->type = REPORT;
    scoped_pdu->error_status = NO_ERROR;
    scoped_pdu->error_index = 0;
    scoped_pdu->num_of_bindings = 1;
    SET_OID(scoped_pdu->bindings[0].oid, SNMP_OID_INVALID_TIME_WINDOW_COUNTER);
    scoped_pdu->bindings[0].type = SMI_TYPE_COUNTER_32;
    scoped_pdu->bindings[0].value.unsigned_integer =
            get_statistics()->usm_stats_not_in_time_windows;

    return build_response_pdu(user, pdu, output_buf, max_pdu_size);
}

static int generate_security_error_response(SnmpUserSlot user, SnmpPDU *pdu,
        buf_t *output_buf, int security_error, int *auth_trap)
{
    switch (security_error) {
        case PROCESSING_SECURITY_LEVEL_INVALID: {
            get_statistics()->usm_stats_unsupported_sec_levels++;
            break;
        }

        case PROCESSING_SECURITY_TIME_INVALID: {
            get_statistics()->usm_stats_not_in_time_windows++;
            break;
        }

        case PROCESSING_SECURITY_AUTH_FAILED: {
            get_statistics()->usm_stats_wrong_digests++;
            break;
        }

        case PROCESSING_SECURITY_ENC_FAILED: {
            get_statistics()->usm_stats_decryption_errors++;
            break;
        }

        default: {
            return generate_error_response(user, RESPONSE, GENERAL_ERROR, 0, pdu,
                    NULL, output_buf);
        }
    }

    *auth_trap = 1;
    return generate_error_response(user, RESPONSE, AUTHORIZATION_ERROR, 0, pdu,
            NULL, output_buf);
}

static int generate_error_response(SnmpUserSlot user, SnmpPduType type,
        SnmpErrorStatus errStatus, int errIndex, SnmpPDU *pdu,
        SnmpScopedPDU *scoped_pdu, buf_t *output_buf)
{
    switch (errStatus) {
        case GENERAL_ERROR: {
            get_statistics()->snmp_out_gen_errs++;
            break;
        }

        case BAD_VALUE: {
            get_statistics()->snmp_out_bad_values++;
            break;
        }

        case NO_SUCH_NAME: {
            get_statistics()->snmp_out_no_such_names++;
            break;
        }

        case TOO_BIG: {
            get_statistics()->snmp_out_too_big++;
            break;
        }

        default: {
            break;
        }
    }

    int max_pdu_size = min(pdu->max_size, MAX_PDU_SIZE);
    SnmpScopedPDU empty_scoped_pdu;

    pdu->scoped_pdu.decrypted_pdu =
            scoped_pdu == NULL ? &empty_scoped_pdu : scoped_pdu;
    pdu->max_size = MAX_PDU_SIZE;
    pdu->requires_response = 0;
    fill_security_header(pdu);
    fill_context_header(pdu->scoped_pdu.decrypted_pdu);
    pdu->scoped_pdu.decrypted_pdu->type = type;
    pdu->scoped_pdu.decrypted_pdu->error_status = errStatus;
    pdu->scoped_pdu.decrypted_pdu->error_index = errIndex;
    if (scoped_pdu == NULL) {
        pdu->scoped_pdu.decrypted_pdu->num_of_bindings = 0;
    }

    return build_response_pdu(user, pdu, output_buf, max_pdu_size);
}

static int build_response_pdu(SnmpUserSlot user, SnmpPDU *pdu,
        buf_t *output_buf, int max_pdu_size)
{
    unsigned int pos_mark = output_buf->pos;

    while (1) {
        if (user == -1) {
            if (!encode_snmp_scoped_pdu(pdu->scoped_pdu.decrypted_pdu, output_buf)
                && !encode_snmp_pdu(pdu, output_buf, output_buf->size - output_buf->pos)
                && output_buf->size - output_buf->pos <= max_pdu_size) {
                return 0;
            }
        } else if (!process_outgoing_pdu(pdu, output_buf, &usm_context[user])
                && output_buf->size - output_buf->pos <= max_pdu_size) {
            return 0;
        }

        if (pdu->scoped_pdu.decrypted_pdu->num_of_bindings > 0) {
            syslog(LOG_DEBUG, "response PDU too big : dropping last var binding");
            pdu->scoped_pdu.decrypted_pdu->num_of_bindings--;

            if (pdu->scoped_pdu.decrypted_pdu->error_status != TOO_BIG) {
                get_statistics()->snmp_out_too_big++;
            }

            if (pdu->scoped_pdu.decrypted_pdu->error_status == NO_ERROR
                || pdu->scoped_pdu.decrypted_pdu->error_status == TOO_BIG) {
                pdu->scoped_pdu.decrypted_pdu->error_status = TOO_BIG;
                pdu->scoped_pdu.decrypted_pdu->error_index =
                    pdu->scoped_pdu.decrypted_pdu->num_of_bindings + 1;
            }
        } else {
            syslog(LOG_WARNING, "failed to encode response PDU : too big");
            return -1;
        }

        output_buf->pos = pos_mark;
    }
}

static void fill_security_header(SnmpPDU *pdu)
{
    pdu->security_parameters.authoritative_engine_boots = get_boot_count();
    pdu->security_parameters.authoritative_engine_time = get_uptime();
    pdu->security_parameters.privacy_parameters_len = 0;
    pdu->security_parameters.authentication_parameters_len = 0;
    uint8_t *engine_id;
    pdu->security_parameters.authoritative_engine_id_len = get_engine_id(&engine_id);
    memcpy(pdu->security_parameters.authoritative_engine_id, engine_id,
            pdu->security_parameters.authoritative_engine_id_len);
}

static void fill_context_header(SnmpScopedPDU *scoped_pdu)
{
    uint8_t *engine_id;
    scoped_pdu->context_engine_id_len = get_engine_id(&engine_id);
    memcpy(scoped_pdu->context_engine_id, engine_id,
            scoped_pdu->context_engine_id_len);
    scoped_pdu->context_engine_name_len = 0;
}

static void increment_incoming_pdu_counter(SnmpScopedPDU *pdu)
{
    switch (pdu->type) {
        case GET:
        case GET_BULK: {
            get_statistics()->snmp_in_get_requests++;
            break;
        }

        case GET_NEXT: {
            get_statistics()->snmp_in_get_nexts++;
            break;
        }

        case SET: {
            get_statistics()->snmp_in_set_requests++;
            break;
        }

        case INFORM:
        case TRAP: {
            get_statistics()->snmp_in_traps++;
            break;
        }

        case RESPONSE: {
            get_statistics()->snmp_in_get_responses++;
            break;
        }

        default: {
            break;
        }
    }
}

static void increment_incoming_error_counter(SnmpScopedPDU *pdu)
{
    switch (pdu->error_status) {
        case BAD_VALUE: {
            get_statistics()->snmp_in_bad_values++;
            break;
        }

        case GENERAL_ERROR: {
            get_statistics()->snmp_in_gen_errs++;
            break;
        }

        case READ_ONLY: {
            get_statistics()->snmp_in_read_only++;
            break;
        }

        case TOO_BIG: {
            get_statistics()->snmp_in_too_big++;
            break;
        }

        case NO_SUCH_NAME: {
            get_statistics()->snmp_in_no_such_names++;
            break;
        }

        default: {
            break;
        }
    }
}

static int init_socket(struct pollfd *poll_descriptor)
{
    if (get_agent_port() <= 1) {
        syslog(LOG_ERR, "failed to create UDP socket : invalid port %"PRIu16, get_agent_port());
        return -1;
    }

    udp_socket_descriptor = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket_descriptor == -1) {
        syslog(LOG_ERR, "failed to create socket : %s", strerror(errno));
        return -1;
    }

    int sockopt = 0;
    if (setsockopt(udp_socket_descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &sockopt,
            sizeof(sockopt)) == -1) {
        syslog(LOG_ERR, "failed to enable dual-stack socket : %s", strerror(errno));
    }

    if (setsockopt(udp_socket_descriptor, IPPROTO_IP, IP_MULTICAST_LOOP,
            &sockopt, sizeof(sockopt)) == -1 || setsockopt(udp_socket_descriptor,
            IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &sockopt, sizeof(sockopt)) == -1) {
        syslog(LOG_ERR, "failed to disable multicast loopback : %s", strerror(errno));
        return -1;
    }

    sockopt = 1;
    if (setsockopt(udp_socket_descriptor, IPPROTO_IPV6, IPV6_RECVPKTINFO,
            &sockopt, sizeof(sockopt)) == -1) {
        syslog(LOG_ERR, "failed to set socket options : %s", strerror(errno));
        return -1;
    }

    if (setsockopt(udp_socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &sockopt,
            sizeof(sockopt)) == -1) {
        syslog(LOG_ERR, "failed to enable address reuse : %s", strerror(errno));
        return -1;
    }

    if (fcntl(udp_socket_descriptor, F_SETFL, O_NONBLOCK) == -1) {
        syslog(LOG_ERR, "failed to set UDP socket non-blocking : %s",
                strerror(errno));
        return -1;
    }

    struct sockaddr_in6 address;
    memset((char *) &address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_port = htons(get_agent_port());
    address.sin6_addr = in6addr_any;
    if (bind(udp_socket_descriptor, (struct sockaddr *) &address, sizeof(address)) == -1) {
        syslog(LOG_ERR, "failed to bind socket : %s", strerror(errno));
        return -1;
    }

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(IP4_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(udp_socket_descriptor, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq,
            sizeof(mreq)) == -1) {
        syslog(LOG_WARNING, "failed to join IPv4 multicast group : %s", strerror(errno));
    }

    struct ipv6_mreq mreq6;
    mreq6.ipv6mr_interface = 0;
    inet_pton(AF_INET6, IP6_GROUP, &mreq6.ipv6mr_multiaddr);
    if (setsockopt(udp_socket_descriptor, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6,
            sizeof(mreq6)) == -1) {
        syslog(LOG_WARNING, "failed to join IPv6 multicast group : %s", strerror(errno));
    }

    poll_descriptor->fd = udp_socket_descriptor;
    poll_descriptor->events = POLLIN;

    syslog(LOG_INFO, "UDP socket initialised");
    return 0;
}

static int init_usm_context(void)
{
    ssize_t len = get_engine_id(&engine_id);
    if (len < 0) {
        syslog(LOG_ERR, "missing engine id");
        return -1;
    }
    engine_id_len = len;

    for (int i = 0; i < NUMBER_OF_USER_SLOTS; i++) {
        UserConfiguration *config = get_user_configuration(i);
        if (config == NULL) {
            syslog(LOG_ERR, "missing configuration for user %i", i);
            return -1;
        } else if (!config->enabled) {
            syslog(LOG_DEBUG, "user %i disabled", i);
            user_enabled[i] = 0;
            continue;
        }

        user_enabled[i] = 1;
        usm_context[i].level = config->security_level;
        usm_context[i].user_name_len = strlen(config->name);
        memcpy(usm_context[i].user_name, config->name, usm_context[i].user_name_len);
        usm_context[i].auth_key_len = 0;
        usm_context[i].priv_key_len = 0;
        usm_context[i].get_engine_boots = 0;
        usm_context[i].get_engine_time = 0;
        usm_context[i].get_engine_boots = get_boot_count;
        usm_context[i].get_engine_time = get_uptime;

        if (config->security_level > NO_AUTH_NO_PRIV) {
            if (derive_usm_master_keys(config->priv_password,
                    config->auth_password, &usm_context[i])) {
                syslog(LOG_ERR, "failed to derive master keyset for user %i", i);
                return -1;
            } else if (derive_usm_diversified_keys(engine_id, engine_id_len, &usm_context[i])) {
                syslog(LOG_ERR, "failed to diversify keyset for user %i", i);
                return -1;
            }
        }
    }

    return 0;
}
