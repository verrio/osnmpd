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

#ifndef SRC_SNMP_AGENT_AGENT_NOTIFICATION_H_
#define SRC_SNMP_AGENT_AGENT_NOTIFICATION_H_

#include <poll.h>

/**
 * @internal
 * init_notification_handler - initialize the notification handler.
 *
 * @param poll_descriptor OUT - poll file descriptor on which to register
 * for incoming notifications
 * @param timeout OUT - timeout on poll
 * @return 0 on success or -1 on any error
 */
int init_notification_handler(struct pollfd *poll_descriptor, int *timeout);

/**
 * @internal
 * finish_notification_handler - finish the notification handler.
 *
 * @return 0 on success or -1 on any error
 */
int finish_notification_handler(void);

/**
 * @internal
 * handle_incoming_notification - handle an incoming SNMP notification.
 */
void handle_incoming_notification(void);

/**
 * @internal
 * dispatch_auth_failed_notification - dispatch an authentication failure trap.
 *
 * @param source IN - source of the authentication failure
 */
void dispatch_auth_failed_notification(const char *source);

#endif /* SRC_SNMP_AGENT_AGENT_NOTIFICATION_H_ */
