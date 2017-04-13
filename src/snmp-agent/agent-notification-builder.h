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

/**
 * @internal
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
 * @internal
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
