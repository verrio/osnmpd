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

#ifndef SRC_SNMP_AGENT_AGENT_INCOMING_H_
#define SRC_SNMP_AGENT_AGENT_INCOMING_H_

#include <poll.h>

/**
 * init_incoming_handler - initialize the handler for incoming user requests.
 *
 * @param poll_descriptor IN/OUT - poll file descriptor on which to register
 * for incoming events
 * @return 0 on success or -1 on any error
 */
int init_incoming_handler(struct pollfd *poll_descriptor);

/**
 * finish_incoming_handler - finish the handler for incoming user requests.
 *
 * @return 0 on success or -1 on any error
 */
int finish_incoming_handler(void);

/**
 * handle_request - handle an incoming SNMP request.
 */
void handle_request(void);

/**
 * update_incoming_keyset - invalidate the USM keysets currently in use.
 */
__attribute__((visibility("default")))
void update_incoming_keyset(void);

#endif /* SRC_SNMP_AGENT_AGENT_INCOMING_H_ */
