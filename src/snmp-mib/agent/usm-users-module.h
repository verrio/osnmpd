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

#ifndef SRC_SNMP_MIB_AGENT_USM_USERS_MODULE_H_
#define SRC_SNMP_MIB_AGENT_USM_USERS_MODULE_H_

#include "snmp-agent/agent-config.h"
#include "snmp-mib/mib-module.h"

/*
 * USM statistics ("usmUser") of the SNMP-USER-BASED-SM-MIB (RFC 3414).
 */

/**
 * get_user_row - returns row index for the given row identifier
 *
 * @row	     IN - row identifier
 * @row_len	 IN - length of row identifier
 * @next_row IN - return row following the given row identifier
 * @return row index, or -1 if no match found.
 */
int get_user_row(SubOID *row, size_t row_len, int next_row);

/**
 * get_row_entry - returns user configuration for given row index.
 *
 * @row	IN - row index
 * @return user configuration for row, or NULL if not available.
 */
UserConfiguration *get_row_entry(int row);

/**
 * get_row_user_name - returns the row's user identifier for a given row
 *
 * @row	IN - row index
 * @return row's user identifier, or NULL if not available.
 */
uint8_t *get_row_user_name(int row);

/**
 * init_usm_users_module - creates and initialises a new USM users module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_usm_users_module(void);

#endif /* SRC_SNMP_MIB_AGENT_USM_USERS_MODULE_H_ */
