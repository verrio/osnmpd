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

#ifndef SRC_SNMP_AGENT_AGENT_NOTIFICATION_BUILDER_H_
#define SRC_SNMP_AGENT_AGENT_NOTIFICATION_BUILDER_H_

#include "snmp-core/snmp-pdu.h"

#define NOTIFICATION_VERSION	0x00

#define CHECK_TRAP_ENC_RESULT(x,y) do { \
    int retval = (x); \
    if (retval != 0) { \
        syslog(LOG_WARNING, "failed to encode %s. (return code %d)", y, retval); \
        return -1; \
    } \
} while (0)

#define CHECK_TRAP_DEC_RESULT(x,y) do { \
    int retval = (x); \
    if (retval != 0) { \
        syslog(LOG_WARNING, "notification decode error: %s. (return code %d)", \
            y, retval); \
        return -1; \
    } \
} while (0)

/* notification type */
typedef struct agent_notification {

    /* trap IDs identifying the notification type */
    uint16_t code_1;
    uint16_t code_2;

    /* associated OID */
    const SubOID *oid;
    size_t oid_len;

    /* argument handling (NULL if no arguments required) */
    int (*add_arguments)(const struct agent_notification *notification,
            buf_t *input_buf, SnmpScopedPDU *output_pdu);

} agent_notification;

/**
 * init_notification_builder - initialise the notification builder.
 *
 * @return 0 on success, negative number on failure
 */
int init_notification_builder(void);

/**
 * add_notification_type - add new notification type.
 *
 * type IN - notification to be added.
 *
 * @return 0 on success, negative number on failure
 */
__attribute__((visibility("default")))
int add_notification_type(const agent_notification *type);

/**
 * build_authentication_failure_notification - build new authorization exception
 * notification.
 *
 * @param source IN - source of authorization failure
 * @param buf OUT - output buffer for resulting notification
 *
 * @return  returns 0 on success, negative value on failure.
 */
int build_authentication_failure_notification(const char *source, buf_t *buf);

/**
 * build_snmp_notification_scoped_pdu - build new trap/inform PDU from
 * received notification.
 *
 * @param source IN - buffer containing received event
 * @param scoped_pdu OUT - resulting PDU
 *
 * @return  returns 0 on success, negative value on failure.
 */
int build_snmp_notification_scoped_pdu(buf_t *source, SnmpScopedPDU *scoped_pdu);

#endif /* SRC_SNMP_AGENT_AGENT_NOTIFICATION_BUILDER_H_ */
