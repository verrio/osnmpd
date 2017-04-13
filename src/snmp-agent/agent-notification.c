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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mqueue.h>
#include <netdb.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-notification.h"
#include "snmp-agent/agent-notification-builder.h"
#include "snmp-core/snmp-crypto.h"
#include "snmp-core/snmp-pdu.h"
#include "snmp-core/tinyber.h"
#include "snmp-core/utils.h"

#define NOTIFICATION_TX_QUEUE	"/snmp-notifications-generated"
#define NOTIFICATION_RX_QUEUE	"/snmp-notifications"
#define MAX_NOTIFICATION_SIZE	512
#define MAX_SNMP_NOTIFICATION_SIZE	1024
#define MAX_RRT   32

enum NotificationHandlerState {

    /* waiting on new notification */
    WAIT_NEW_NOTIFICATION,

    /* wait before retry */
    WAIT_BEFORE_RETRY,

    /* waiting on engine id discovery */
    WAIT_ENGINE_DISCOVERY,

    /* waiting on clock sync */
    WAIT_CLOCK_SYNC,

    /* waiting on notification confirmation */
    WAIT_NOTIFICATION_CONFIRMATION

};

typedef struct {

    /* current notification handler state */
    enum NotificationHandlerState state;

    /* USM context for outgoing notifications */
    SnmpUSMContext usm_ctx;

    /* destination engine ID */
    uint8_t *engine_id;
    size_t engine_id_len;

    /* destination time deviation */
    uint32_t boot_count;
    int32_t time_deviation;

    /* amount of retries attempted */
    int retry_count;

    /* amount of messages sent (avoid looping on malfunctioning client) */
    int rrt_count;

    /* indicates one or more config parameters are missing */
    int drop;

    /* message counters */
    uint32_t msg_id;
    uint32_t request_id;

    /* poll file descriptor */
    struct pollfd *pd;
    int *timeout;

    /* incoming/outgoing notification queue */
    mqd_t incoming_queue;
    mqd_t outgoing_queue;

    /* notification socket */
    int sock;
    struct addrinfo *sock_dst;

    /* buffer for incoming notifications */
    uint8_t rx_buf[MAX_NOTIFICATION_SIZE];

    /* last notification */
    SnmpPDU notification;
    SnmpScopedPDU content;

} NotificationHandlerContext;

static NotificationHandlerContext notification_ctx;

static void dispatch_notification(void);
static void discover_engine_id(void);
static void sync_destination_clock(void);
static int send_pdu(uint8_t *, size_t);
static int receive_pdu(SnmpPDU *, SnmpScopedPDU *);
static void handle_new_notification(void);
static void handle_engine_discovery(void);
static void handle_clock_sync(void);
static void handle_notification_confirmation(void);
static void enter_wait_for_retry(void);
static void enter_wait_for_new_notification(int);
static void enter_wait_for_response(enum NotificationHandlerState);

static uint32_t get_notification_boot_count(void)
{
    return notification_ctx.boot_count;
}

static uint32_t get_notification_time(void)
{
    return get_uptime() + notification_ctx.time_deviation;
}

static int init_master_keyset(void)
{
    UserConfiguration *user_config = get_user_configuration(
            get_trap_configuration()->user);
    if (user_config == NULL || derive_usm_master_keys(user_config->priv_password,
        user_config->auth_password, &notification_ctx.usm_ctx)) {
        syslog(LOG_ERR, "failed to derive master secrets for notification handler.");
        return -1;
    }

    return 0;
}

static int init_state(void)
{
    notification_ctx.state = WAIT_NEW_NOTIFICATION;
    notification_ctx.sock = -1;
    notification_ctx.sock_dst = NULL;
    notification_ctx.retry_count = 0;
    notification_ctx.rrt_count = 0;
    notification_ctx.engine_id = NULL;
    notification_ctx.boot_count = get_boot_count();
    notification_ctx.time_deviation = 0;
    notification_ctx.drop = 0;
    notification_ctx.msg_id = 0;
    notification_ctx.request_id = 0;
    notification_ctx.incoming_queue = -1;
    notification_ctx.outgoing_queue = -1;

    if (get_trap_configuration()->user != -1) {
        UserConfiguration *user_config =
                get_user_configuration(get_trap_configuration()->user);
        if (user_config != NULL) {
            strcpy(notification_ctx.usm_ctx.user_name, user_config->name);
            notification_ctx.usm_ctx.user_name_len = strlen(user_config->name);
            notification_ctx.usm_ctx.level = user_config->security_level;
        } else {
            notification_ctx.usm_ctx.user_name_len = 0;
            notification_ctx.usm_ctx.level = NO_AUTH_NO_PRIV;
        }
    } else {
        notification_ctx.usm_ctx.user_name_len = 0;
        notification_ctx.usm_ctx.level = NO_AUTH_NO_PRIV;
    }

    notification_ctx.usm_ctx.get_engine_boots = get_notification_boot_count;
    notification_ctx.usm_ctx.get_engine_time = get_notification_time;

    if (!get_trap_configuration()->confirmed) {
        uint8_t *engine_id;
        size_t engine_id_len = get_engine_id(&engine_id);
        if (init_master_keyset()
            || derive_usm_diversified_keys(engine_id, engine_id_len,
                    &notification_ctx.usm_ctx)) {
            syslog(LOG_ERR, "keyset unavailable : notifications unavailable");
            goto err;
        }
    }

    return 0;
    err: notification_ctx.drop = 1;
    return -1;
}

int init_notification_handler(struct pollfd *poll_descriptor, int *timeout)
{
    notification_ctx.pd = poll_descriptor;
    notification_ctx.timeout = timeout;

    /* init handler state */
    int ret_val = init_state();

    /* init message queues */
    struct mq_attr queue_attr;
    queue_attr.mq_flags = 0;
    queue_attr.mq_maxmsg = 64;
    queue_attr.mq_msgsize = MAX_NOTIFICATION_SIZE;
    queue_attr.mq_curmsgs = 0;

    notification_ctx.incoming_queue = mq_open(NOTIFICATION_RX_QUEUE,
            O_CREAT | O_RDONLY | O_NONBLOCK, 0666, &queue_attr);
    if (notification_ctx.incoming_queue == (mqd_t) -1) {
        syslog(LOG_ERR, "failed to open incoming notification queue : %s",
                strerror(errno));
        ret_val = -1;
    }
    notification_ctx.pd->fd = notification_ctx.incoming_queue;
    notification_ctx.pd->events = POLLIN;

    notification_ctx.outgoing_queue = mq_open(NOTIFICATION_TX_QUEUE,
            O_CREAT | O_WRONLY | O_NONBLOCK, 0666, &queue_attr);
    if (notification_ctx.outgoing_queue == (mqd_t) -1) {
        syslog(LOG_ERR, "failed to open outgoing message queue : %s",
                strerror(errno));
        ret_val = -1;
    }

    return ret_val;
}

int finish_notification_handler(void)
{
    if (notification_ctx.engine_id != NULL) {
        free(notification_ctx.engine_id);
        notification_ctx.engine_id = NULL;
    }

    if (notification_ctx.incoming_queue != -1) {
        mq_close(notification_ctx.incoming_queue);
        notification_ctx.incoming_queue = -1;
        notification_ctx.pd->fd = -1;
    }

    if (notification_ctx.outgoing_queue != -1) {
        mq_close(notification_ctx.outgoing_queue);
        notification_ctx.outgoing_queue = -1;
    }

    if (notification_ctx.sock != -1) {
        close(notification_ctx.sock);
    }

    if (notification_ctx.sock_dst != NULL) {
        freeaddrinfo(notification_ctx.sock_dst);
        notification_ctx.sock_dst = NULL;
    }

    return 0;
}

void dispatch_auth_failed_notification(const char *source)
{
    if (notification_ctx.outgoing_queue == -1) {
        syslog(LOG_ERR, "dropping notification : message queue not available");
        goto failed;
    }

    uint8_t buf[MAX_NOTIFICATION_SIZE];
    buf_t buffer;
    init_obuf(&buffer, buf, MAX_NOTIFICATION_SIZE);

    if (build_authentication_failure_notification(source, &buffer)) {
        goto failed;
    }

    /* don't block, even if notification queue is full */
    if (mq_send(notification_ctx.outgoing_queue, (char *) &buffer.buffer[buffer.pos],
            buffer.size - buffer.pos, 0) == -1) {
        syslog(LOG_ERR, "failed to dispatch notification : %s", strerror(errno));
        goto failed;
    }

    return;
    failed: get_statistics()->failed_outbound_counter++;
}

void handle_incoming_notification(void)
{
    switch (notification_ctx.state) {
        case WAIT_NEW_NOTIFICATION: {
            handle_new_notification();
            break;
        }

        case WAIT_BEFORE_RETRY: {
            dispatch_notification();
            break;
        }

        case WAIT_ENGINE_DISCOVERY: {
            handle_engine_discovery();
            break;
        }

        case WAIT_CLOCK_SYNC: {
            handle_clock_sync();
            break;
        }

        case WAIT_NOTIFICATION_CONFIRMATION: {
            handle_notification_confirmation();
            break;
        }

        default: {
            syslog(LOG_ERR, "notification handler in unknown state.");
            enter_wait_for_new_notification(1);
        }
    }
}

static void dispatch_notification(void)
{
    TrapConfiguration *config = get_trap_configuration();

    if (config->confirmed && notification_ctx.engine_id == NULL) {
        discover_engine_id();
        return;
    }

    /* build notification */
    notification_ctx.notification.message_id = notification_ctx.retry_count ?
            notification_ctx.msg_id : ++notification_ctx.msg_id;
    notification_ctx.notification.max_size = MAX_SNMP_NOTIFICATION_SIZE;
    notification_ctx.notification.is_encrypted =
            notification_ctx.usm_ctx.level > AUTH_NO_PRIV;
    notification_ctx.notification.is_authenticated =
            notification_ctx.usm_ctx.level > NO_AUTH_NO_PRIV;
    notification_ctx.notification.requires_response = config->confirmed;
    memcpy(notification_ctx.notification.security_parameters.user_name,
            notification_ctx.usm_ctx.user_name, notification_ctx.usm_ctx.user_name_len);
    notification_ctx.notification.
        security_parameters.user_name[notification_ctx.usm_ctx.user_name_len] = '\0';
    notification_ctx.notification.security_parameters.privacy_parameters_len = 0;
    notification_ctx.notification.security_parameters.authentication_parameters_len = 0;
    notification_ctx.notification.security_parameters.authoritative_engine_boots =
            notification_ctx.usm_ctx.level > NO_AUTH_NO_PRIV ?
                    get_notification_boot_count() : 0;
    notification_ctx.notification.security_parameters.authoritative_engine_time =
            notification_ctx.usm_ctx.level > NO_AUTH_NO_PRIV ? get_notification_time() : 0;
    notification_ctx.notification.scoped_pdu.decrypted_pdu = &notification_ctx.content;
    notification_ctx.content.request_id = notification_ctx.request_id++;
    notification_ctx.content.type = config->confirmed ? INFORM : TRAP;
    notification_ctx.content.error_status = NO_ERROR;
    notification_ctx.content.error_index = 0;
    notification_ctx.content.context_engine_name_len = 0;
    if (config->confirmed) {
        memcpy(notification_ctx.content.context_engine_id,
               notification_ctx.engine_id, notification_ctx.engine_id_len);
        notification_ctx.content.context_engine_id_len = notification_ctx.engine_id_len;
        memcpy(notification_ctx.notification.security_parameters.authoritative_engine_id,
               notification_ctx.engine_id, notification_ctx.engine_id_len);
        notification_ctx.notification.security_parameters.authoritative_engine_id_len =
                notification_ctx.engine_id_len;
    } else {
        uint8_t *engine_id;
        notification_ctx.content.context_engine_id_len = get_engine_id(&engine_id);
        notification_ctx.notification.security_parameters.authoritative_engine_id_len =
                notification_ctx.content.context_engine_id_len;
        memcpy(notification_ctx.content.context_engine_id, engine_id,
               notification_ctx.content.context_engine_id_len);
        memcpy(notification_ctx.notification.security_parameters.authoritative_engine_id,
               engine_id, notification_ctx.content.context_engine_id_len);
    }

    uint8_t tx_buffer[MAX_SNMP_NOTIFICATION_SIZE];
    buf_t tx_buf;
    init_obuf(&tx_buf, tx_buffer, sizeof(tx_buffer));
    if (process_outgoing_pdu(&notification_ctx.notification,
            &tx_buf, &notification_ctx.usm_ctx)) {
        syslog(LOG_WARNING, "failed to marshal outgoing notification");
        enter_wait_for_new_notification(1);
        return;
    }

    if (send_pdu(&tx_buf.buffer[tx_buf.pos], tx_buf.size - tx_buf.pos)) {
        enter_wait_for_retry();
    } else if (config->confirmed) {
        get_statistics()->last_outbound_timestamp = get_uptime();
        enter_wait_for_response(WAIT_NOTIFICATION_CONFIRMATION);
    } else {
        get_statistics()->last_outbound_timestamp = get_uptime();
        get_statistics()->snmp_out_traps++;
        enter_wait_for_new_notification(0);
    }
}

static void discover_engine_id(void)
{
    syslog(LOG_INFO, "discovering notification destination engine id");

    SnmpPDU pdu;
    pdu.message_id = notification_ctx.msg_id++;
    pdu.max_size = MAX_SNMP_NOTIFICATION_SIZE;
    pdu.is_encrypted = 0;
    pdu.is_authenticated = 0;
    pdu.requires_response = 1;
    pdu.security_parameters.user_name[0] = '\0';
    pdu.security_parameters.authoritative_engine_id_len = 0;
    pdu.security_parameters.privacy_parameters_len = 0;
    pdu.security_parameters.authentication_parameters_len = 0;
    pdu.security_parameters.authoritative_engine_boots = 0;
    pdu.security_parameters.authoritative_engine_time = 0;
    SnmpScopedPDU scoped_pdu;
    pdu.scoped_pdu.decrypted_pdu = &scoped_pdu;
    scoped_pdu.request_id = notification_ctx.request_id++;
    scoped_pdu.type = GET;
    scoped_pdu.error_status = NO_ERROR;
    scoped_pdu.error_index = 0;
    scoped_pdu.context_engine_id_len = 0;
    scoped_pdu.context_engine_name_len = 0;
    scoped_pdu.num_of_bindings = 0;

    uint8_t buf[MAX_SNMP_NOTIFICATION_SIZE];
    buf_t tx_buf;
    init_obuf(&tx_buf, buf, sizeof(buf));

    if (encode_snmp_scoped_pdu(&scoped_pdu, &tx_buf)
            || encode_snmp_pdu(&pdu, &tx_buf, tx_buf.size - tx_buf.pos)) {
        syslog(LOG_ERR, "failed to marshal engine discovery request");
        enter_wait_for_new_notification(0);
    } else if (send_pdu(&tx_buf.buffer[tx_buf.pos], tx_buf.size - tx_buf.pos)) {
        enter_wait_for_retry();
    } else {
        get_statistics()->snmp_out_get_requests++;
        enter_wait_for_response(WAIT_ENGINE_DISCOVERY);
    }
}

static void sync_destination_clock(void)
{
    syslog(LOG_INFO, "syncing clock with notification destination");

    SnmpPDU pdu;
    pdu.message_id = notification_ctx.msg_id++;
    pdu.max_size = MAX_SNMP_NOTIFICATION_SIZE;
    pdu.is_encrypted = 0;
    pdu.is_authenticated = 1;
    pdu.requires_response = 1;
    memcpy(pdu.security_parameters.user_name, notification_ctx.usm_ctx.user_name,
            notification_ctx.usm_ctx.user_name_len);
    pdu.security_parameters.user_name[notification_ctx.usm_ctx.user_name_len] = '\0';
    pdu.security_parameters.privacy_parameters_len = 0;
    pdu.security_parameters.authentication_parameters_len = 0;
    pdu.security_parameters.authoritative_engine_boots = 0;
    pdu.security_parameters.authoritative_engine_time = 0;
    memcpy(pdu.security_parameters.authoritative_engine_id,
       notification_ctx.engine_id, notification_ctx.engine_id_len);
    pdu.security_parameters.authoritative_engine_id_len = notification_ctx.engine_id_len;
    SnmpScopedPDU scoped_pdu;
    pdu.scoped_pdu.decrypted_pdu = &scoped_pdu;
    scoped_pdu.request_id = notification_ctx.request_id++;
    scoped_pdu.type = GET;
    scoped_pdu.error_status = NO_ERROR;
    scoped_pdu.error_index = 0;
    memcpy(scoped_pdu.context_engine_id, notification_ctx.engine_id,
            notification_ctx.engine_id_len);
    scoped_pdu.context_engine_id_len = notification_ctx.engine_id_len;
    scoped_pdu.context_engine_name_len = 0;
    scoped_pdu.num_of_bindings = 0;

    uint8_t buf[MAX_SNMP_NOTIFICATION_SIZE];
    buf_t tx_buf;
    init_obuf(&tx_buf, buf, sizeof(buf));

    /* disable encryption */
    SnmpSecurityLevel orig_level = notification_ctx.usm_ctx.level;
    notification_ctx.usm_ctx.level = AUTH_NO_PRIV;
    int ret = process_outgoing_pdu(&pdu, &tx_buf, &notification_ctx.usm_ctx);
    notification_ctx.usm_ctx.level = orig_level;

    if (ret) {
        syslog(LOG_ERR, "failed to marshal clock sync request");
        enter_wait_for_new_notification(0);
    } else if (send_pdu(&tx_buf.buffer[tx_buf.pos], tx_buf.size - tx_buf.pos)) {
        enter_wait_for_retry();
    } else {
        get_statistics()->snmp_out_get_requests++;
        enter_wait_for_response(WAIT_CLOCK_SYNC);
    }
}

static int send_pdu(uint8_t *pdu, size_t pdu_len)
{
    notification_ctx.retry_count++;
    notification_ctx.rrt_count++;

    if (notification_ctx.sock == -1) {
        if (notification_ctx.sock_dst != NULL) {
            freeaddrinfo(notification_ctx.sock_dst);
            notification_ctx.sock_dst = NULL;
        }

        TrapConfiguration *config = get_trap_configuration();
        if (config->destination == NULL || config->port == 0) {
            syslog(LOG_WARNING, "missing notification destination");
            goto err;
        }

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        char port[5];
        sprintf(port, "%"PRIu16, config->port);
        int yes = 1;
        struct timeval timeout;
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        /* TODO: don't block on address resolution */
        int ret;
        if ((ret = getaddrinfo(config->destination, port, &hints,
                &notification_ctx.sock_dst)) != 0) {
            syslog(LOG_WARNING, "failed to resolve notification destination  : %s",
                    gai_strerror(ret));
            goto err;
        }

        struct addrinfo *dst;
        for (dst = notification_ctx.sock_dst; dst != NULL; dst = dst->ai_next) {
            if ((notification_ctx.sock = socket(dst->ai_family, dst->ai_socktype,
                    dst->ai_protocol)) == -1) {
                syslog(LOG_WARNING, "failed to create notification socket : %s",
                        strerror(errno));
            } else {
                break;
            }
        }
        if (dst == NULL) {
            goto err;
        } else if (setsockopt(notification_ctx.sock, SOL_SOCKET, SO_REUSEADDR,
                &yes, sizeof(yes)) != 0 || setsockopt(notification_ctx.sock,
                        SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) != 0) {
            syslog(LOG_WARNING, "failed to set socket options : %s", strerror(errno));
            goto err;
        } else if (connect(notification_ctx.sock, notification_ctx.sock_dst->ai_addr,
            notification_ctx.sock_dst->ai_addrlen)) {
            syslog(LOG_WARNING, "failed to connect socket : %s", strerror(errno));
            goto err;
        }
    }

    if (sendto(notification_ctx.sock, pdu, pdu_len, 0,
        notification_ctx.sock_dst->ai_addr, notification_ctx.sock_dst->ai_addrlen) == -1) {
        syslog(LOG_WARNING, "failed to dispatch notification : %s", strerror(errno));
        goto err;
    }

    get_statistics()->snmp_out_pkts++;
    return 0;
    err: get_statistics()->snmp_silent_drops++;
    if (notification_ctx.sock != -1) {
        close(notification_ctx.sock);
        notification_ctx.sock = -1;
    }
    return -1;
}

static int receive_pdu(SnmpPDU *pdu, SnmpScopedPDU *scoped_pdu)
{
    uint8_t rx_buf[MAX_SNMP_NOTIFICATION_SIZE];
    ssize_t rx_size = recvfrom(notification_ctx.sock, rx_buf, sizeof(rx_buf),
            MSG_DONTWAIT, NULL, 0);

    if (rx_size < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            syslog(LOG_WARNING, "did not receive response to notification request");
        } else {
            syslog(LOG_WARNING, "failed to receive notification response : %s",
                    strerror(errno));
        }
        return -1;
    }

    get_statistics()->snmp_in_pkts++;

    buf_t buf;
    asn1raw_t pdu_tlv;
    init_ibuf(&buf, rx_buf, rx_size);
    if (decode_TLV(&pdu_tlv, &buf)) {
        syslog(LOG_WARNING, "incoming notification response is not a valid BER TLV");
        return -1;
    } else if (decode_snmp_pdu(&pdu_tlv, pdu)) {
        syslog(LOG_WARNING, "failed to decode incoming notification response");
        return -1;
    } else if (scoped_pdu != NULL
            && process_incoming_pdu(pdu, scoped_pdu, &notification_ctx.usm_ctx, 0)) {
        syslog(LOG_WARNING, "failed to process incoming notification response");
        return -1;
    }

    return 0;
}

static void handle_new_notification(void)
{
    ssize_t notification_len = mq_receive(notification_ctx.incoming_queue,
            (char *) notification_ctx.rx_buf, sizeof(notification_ctx.rx_buf), NULL);

    if (notification_len <= 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            syslog(LOG_ERR, "failed to handle incoming notification : %s",
                    strerror(errno));
        }
        return;
    } else if (!get_trap_configuration()->enabled) {
        syslog(LOG_DEBUG, "dropping incoming notification");
        return;
    } else if (notification_ctx.drop) {
        syslog(LOG_ERR, "failed to handle incoming notification : configuration invalid");
        return;
    }

    buf_t buf;
    init_ibuf(&buf, notification_ctx.rx_buf, notification_len);
    notification_ctx.content.num_of_bindings = 0;
    if (build_snmp_notification_scoped_pdu(&buf, &notification_ctx.content)) {
        return;
    }

    dispatch_notification();
}

static void handle_engine_discovery(void)
{
    SnmpPDU pdu;
    if (receive_pdu(&pdu, NULL)) {
        syslog(LOG_WARNING, "engine discovery failed");
        goto retry;
    }

    if (pdu.security_parameters.authoritative_engine_id_len > MAX_ENGINE_ID_LENGTH) {
        syslog(LOG_WARNING, "received engine id too big");
        goto retry;
    }

    notification_ctx.engine_id = malloc(sizeof(uint8_t) *
            pdu.security_parameters.authoritative_engine_id_len);
    if (notification_ctx.engine_id == NULL) {
        goto retry;
    }
    memcpy(notification_ctx.engine_id, pdu.security_parameters.authoritative_engine_id,
        pdu.security_parameters.authoritative_engine_id_len);
    notification_ctx.engine_id_len = pdu.security_parameters.authoritative_engine_id_len;

    char engine_id_dump[3 + (MAX_ENGINE_ID_LENGTH << 1)];
    if (to_hex(notification_ctx.engine_id, notification_ctx.engine_id_len,
            engine_id_dump, sizeof(engine_id_dump))) {
        syslog(LOG_INFO, "notification destination engine id : %s", engine_id_dump);
    }

    if (notification_ctx.usm_ctx.level < AUTH_NO_PRIV) {
        notification_ctx.retry_count = 0;
        notification_ctx.boot_count = 0;
        notification_ctx.time_deviation = 0;
        dispatch_notification();
    } else if (init_master_keyset()
        || derive_usm_diversified_keys(notification_ctx.engine_id,
        notification_ctx.engine_id_len, &notification_ctx.usm_ctx)) {
        syslog(LOG_ERR, "keyset unavailable : dropping notification");
        enter_wait_for_new_notification(1);
        return;
    } else {
        notification_ctx.retry_count = 0;
        sync_destination_clock();
    }

    return;
retry:
    enter_wait_for_retry();
}

static void handle_clock_sync(void)
{
    SnmpPDU pdu;
    /* you'd expect an authentication tag in the response as well,
     * but apparently not all SNMP clients do this, so we can't verify the given parameters...
     */
    if (receive_pdu(&pdu, NULL)
        || (pdu.security_parameters.authoritative_engine_boots == 0
        && pdu.security_parameters.authoritative_engine_time == 0)) {
        syslog(LOG_WARNING, "clock sync failed");
        enter_wait_for_retry();
    } else {
        notification_ctx.retry_count = 0;
        notification_ctx.boot_count =
                pdu.security_parameters.authoritative_engine_boots;
        notification_ctx.time_deviation =
                pdu.security_parameters.authoritative_engine_time - get_uptime();
        dispatch_notification();
    }
}

static void handle_notification_confirmation(void)
{
    SnmpPDU pdu;
    SnmpScopedPDU scoped_pdu;

    if (receive_pdu(&pdu, &scoped_pdu)) {
        syslog(LOG_WARNING, "did not receive valid notification confirmation in time");
        enter_wait_for_retry();
    } else if (scoped_pdu.type != RESPONSE || scoped_pdu.error_status != NO_ERROR
            || scoped_pdu.error_index != 0) {
        syslog(LOG_WARNING, "received confirmation with error status %u, index %u",
            scoped_pdu.error_status, scoped_pdu.error_index);
        if (notification_ctx.engine_id_len !=
            pdu.security_parameters.authoritative_engine_id_len
            || memcmp(notification_ctx.engine_id,
                    pdu.security_parameters.authoritative_engine_id,
                    notification_ctx.engine_id_len)) {
            free(notification_ctx.engine_id);
            notification_ctx.engine_id = NULL;
            notification_ctx.engine_id_len = 0;
        }
        enter_wait_for_retry();
    } else {
        enter_wait_for_new_notification(0);
    }
}

static void enter_wait_for_retry(void)
{
    TrapConfiguration *config = get_trap_configuration();

    if (notification_ctx.retry_count > config->retries
        || notification_ctx.rrt_count > MAX_RRT) {
        syslog(LOG_WARNING, "failed to dispatch notification after multiple retries");
        enter_wait_for_new_notification(1);
    } else {
        notification_ctx.state = WAIT_BEFORE_RETRY;
        notification_ctx.pd->fd = -1;
        notification_ctx.pd->events = POLLIN;
        *notification_ctx.timeout = config->timeout * 1000 *
                (1 << (notification_ctx.retry_count - 1));
    }
}

static void enter_wait_for_new_notification(int failure)
{
    if (failure) {
        syslog(LOG_DEBUG, "marking notification handler state inconsistent");
        if (notification_ctx.engine_id != NULL) {
            free(notification_ctx.engine_id);
            notification_ctx.engine_id = NULL;
        }
        get_statistics()->failed_outbound_counter++;
    }
    if (notification_ctx.sock != -1) {
        close(notification_ctx.sock);
        notification_ctx.sock = -1;
    }

    notification_ctx.retry_count = 0;
    notification_ctx.rrt_count = 0;
    notification_ctx.state = WAIT_NEW_NOTIFICATION;
    notification_ctx.pd->fd = notification_ctx.incoming_queue;
    notification_ctx.pd->events = POLLIN;
    *notification_ctx.timeout = -1;
}

static void enter_wait_for_response(enum NotificationHandlerState new_state)
{
    notification_ctx.state = new_state;
    notification_ctx.pd->fd = notification_ctx.sock;
    notification_ctx.pd->events = POLLIN;
    *notification_ctx.timeout = get_trap_configuration()->timeout * 1000;
}
