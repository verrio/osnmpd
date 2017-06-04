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

#ifndef SRC_SNMP_AGENT_AGENT_NOTIFICATION_LOG_H_
#define SRC_SNMP_AGENT_AGENT_NOTIFICATION_LOG_H_

#include "snmp-agent/agent-notification.h"
#include "snmp-core/snmp-pdu.h"

typedef struct {

    /* index in log */
    uint32_t index;

    /* time of notification (uptime in seconds, timestamp in millis) */
    uint32_t uptime;
    uint64_t timestamp;

    /* trap identifier */
    OID trap_type;

    /* associated variable bindings */
    SnmpVariableBinding vars[MAX_SNMP_VAR_BINDINGS];
    size_t num_of_vars;

} LoggedTrapEntry;

/**
 * init_trap_log - Opens the trap log.
 *
 * @return 0 on success, -1 on storage error.
 */
int init_trap_log(void);

/**
 * finish_trap_log - Closes the trap log.
 *
 * @return 0 on success, -1 on storage error.
 */
int finish_trap_log(void);

/**
 * store_new_log_entry - Stores a new trap to the log.
 *
 * @param scoped_pdu IN - Scoped PDU of the generated trap.
 *
 * @return 0 on success, -1 on storage error.
 */
int store_new_log_entry(const SnmpScopedPDU *const scoped_pdu);

/**
 * get_trap_entry - Retrieves the first logged trap matching the given parameters.
 *
 * @param index IN - Minimum index in log.
 * @param var_filter IN - Variable binding type which should be included in the trap.
 * @param dst OUT - destination output.
 *
 * @return 0 on success, -1 when no results were found.
 */
__attribute__((visibility("default")))
int get_trap_entry(uint32_t index, SMIType var_filter, LoggedTrapEntry *dst);

/**
 * get_num_log_entries - Returns the number of logged traps.
 *
 * @return amount of logged traps.
 */
__attribute__((visibility("default")))
uint32_t get_num_log_entries(void);

/**
 * get_max_log_entries - Returns the maximum number of logged traps.
 *
 * @return Maximum number of logged traps.
 */
__attribute__((visibility("default")))
uint32_t get_max_log_entries(void);

/**
 * get_num_log_discarded - Returns the number of discarded notifications
 * since the last agent restart.
 *
 * @return amount of discarded notifications since the last agent restart.
 */
__attribute__((visibility("default")))
uint32_t get_num_log_discarded(void);

#endif /* SRC_SNMP_AGENT_AGENT_NOTIFICATION_LOG_H_ */
