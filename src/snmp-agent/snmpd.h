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

#ifndef SRC_SNMPD_H_
#define SRC_SNMPD_H_

#define SNMPD_RUN_PATH     "/var/run/snmp/"

/* user profiles available on the agent */
typedef enum {
	USER_PUBLIC = 0,
	USER_READ_ONLY = 1,
	USER_READ_WRITE = 2,
	USER_ADMIN = 3,
	NUMBER_OF_USER_SLOTS = 4
} SnmpUserSlot;

/**
 * @internal
 * set_debug_logging - enables/disables the debug logging
 *
 * @param enabled IN - new debug logging state
 */
void set_debug_logging(int enabled);

/**
 * @internal
 * debug_logging_enabled - returns the debug logging state.
 *
 * @return 0 when disabled, 1 when enabled.
 */
int debug_logging_enabled(void);

#endif /* SRC_SNMPD_H_ */
