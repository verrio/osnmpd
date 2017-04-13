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

#ifndef SRC_SNMP_AGENT_MIB_TREE_H_
#define SRC_SNMP_AGENT_MIB_TREE_H_

#include <syslog.h>

#include "config.h"
#include "snmp-core/snmp-pdu.h"
#include "snmp-mib/mib-module.h"

#define SNMP_OID_INTERNET                1,3,6,1
#define SNMP_OID_ENTERPRISES             SNMP_OID_INTERNET,4,1
#define SNMP_OID_ENTERPRISE_MIB          ENTERPRISE_MIB
#define SNMP_OID_MIB2                    SNMP_OID_INTERNET,2,1
#define SNMP_OID_SNMPV2                  SNMP_OID_INTERNET,6
#define SNMP_OID_SNMPMODULES             SNMP_OID_SNMPV2,3
#define SNMP_OID_SYSTEM_MIB              SNMP_OID_MIB2,1
#define SNMP_OID_NETWORK_APPLICATION_MIB SNMP_OID_MIB2,27
#define SNMP_OID_BATTERY_MIB             SNMP_OID_MIB2,233
#define SNMP_OID_STATS_MIB               SNMP_OID_SNMPV2,3,15,1,1
#define SNMP_OID_FRAMEWORK_MIB           SNMP_OID_SNMPMODULES,10
#define SNMP_OID_MPD_STATS_MIB           SNMP_OID_SNMPMODULES,11
#define SNMP_OID_USM_MIB                 SNMP_OID_SNMPMODULES,15
#define SNMP_OID_VACM                    SNMP_OID_SNMPMODULES,16

/* USM counters */
#define SNMP_OID_UNKNOWN_ENGINE_ID_COUNTER   SNMP_OID_STATS_MIB,4,0
#define SNMP_OID_INVALID_TIME_WINDOW_COUNTER SNMP_OID_STATS_MIB,2,0

/**
 * @internal
 * init_mib_tree - initialise the MIB tree.
 *
 * @return 0 on success, negative number on failure
 */
int init_mib_tree(void);

/**
 * @internal
 * finish_mib_tree - finalise the MIB tree.
 *
 * @return 0 on success, negative number on failure
 */
int finish_mib_tree(void);

/**
 * @internal
 * add_module - add new module to the tree.
 *
 * module_gen IN - module factory.
 * mod_name   IN - module name
 *
 * @return 0 on success, negative number on failure
 */
int add_module(MibModule *(*module_gen)(void), char *mod_name);

/**
 * @internal
 * add_app_module - add network application module to the tree.
 *
 * app_module IN - module.
 *
 * @return 0 on success, negative number on failure
 */
int add_app_module(MibApplicationModule *app_module);

/**
 * @internal
 * dump_mib_tree - print MIB tree to the system log.
 */
void dump_mib_tree(void);

/**
 * @internal
 * mib_get_or_entries - return list of OR registered entries in the MIB.
 *
 * @return pointer to first OR entry in the list, or NULL if empty
 */
SysOREntry *mib_get_or_entries(void);

/**
 * @internal
 * mib_get_app_modules - return list of network
 * application modules registered entries in the MIB.
 *
 * @return pointer to first application module in the list, or NULL if empty
 */
MibApplicationModule *mib_get_app_modules(void);

/**
 * @internal
 * mib_get_entry - fetch the value associated with an entry in the MIB.
 *
 * @param binding IN/OUT - binding containing OID of entry to be fetched.
 * result is stored in associated value attribute.
 * allocated octet-string values are to be freed by the caller.
 *
 * @return 0 on success or suiting SNMP error status on failure
 */
SnmpErrorStatus mib_get_entry(SnmpVariableBinding *binding);

/**
 * @internal
 * mib_get_next_entry - fetch the value associated with an entry
 * following the given OID in the MIB.
 *
 * @param binding IN/OUT - binding containing OID of the predecessor
 * entry to be fetched.  OID and resulting value are stored in the given struct.
 * allocated octet-string values are to be freed by the caller.
 *
 * @return 0 on success or suiting SNMP error status on failure
 */
SnmpErrorStatus mib_get_next_entry(SnmpVariableBinding *binding);

/**
 * @internal
 * mib_set_entry - set/create the value associated with an entry
 * following the given OID in the MIB.
 *
 * @param binding IN - binding containing OID and value of entry to be created/updated.
 * @param dry_run IN - indicates if request should be verified without execution.
 *
 * @return 0 on success or suiting SNMP error status on failure
 */
SnmpErrorStatus mib_set_entry(SnmpVariableBinding *binding, int dry_run);

#endif /* SRC_SNMP_AGENT_MIB_TREE_H_ */
