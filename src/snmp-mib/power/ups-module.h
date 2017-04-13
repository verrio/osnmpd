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

#ifndef SRC_SNMP_MIB_POWER_UPS_MODULE_H_
#define SRC_SNMP_MIB_POWER_UPS_MODULE_H_

#include "snmp-agent/mib-tree.h"
#include "snmp-mib/mib-module.h"

/* object groups of the UPS-MIB at 1.3.6.1.2.1.33.1 (RFC 1628) */
#define SNMP_OID_UPS_OBJECTS SNMP_OID_MIB2,33,1
#define SNMP_OID_UPS_IDENT_OBJECTS SNMP_OID_UPS_OBJECTS,1
#define SNMP_OID_UPS_BATTERY_OBJECTS SNMP_OID_UPS_OBJECTS,2
#define SNMP_OID_UPS_INPUT_OBJECTS SNMP_OID_UPS_OBJECTS,3
#define SNMP_OID_UPS_OUTPUT_OBJECTS SNMP_OID_UPS_OBJECTS,4
#define SNMP_OID_UPS_BYPASS_OBJECTS SNMP_OID_UPS_OBJECTS,5
#define SNMP_OID_UPS_ALARM_OBJECTS SNMP_OID_UPS_OBJECTS,6
#define SNMP_OID_UPS_TEST_OBJECTS SNMP_OID_UPS_OBJECTS,7
#define SNMP_OID_UPS_CONTROL_OBJECTS SNMP_OID_UPS_OBJECTS,8
#define SNMP_OID_UPS_CONFIG_OBJECTS SNMP_OID_UPS_OBJECTS,9

/**
 * @internal
 * init_ups_ident_module - creates and initialises a new UPS ident module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_ident_module(void);

/**
 * @internal
 * init_ups__module - creates and initialises a new UPS module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_battery_module(void);

/**
 * @internal
 * init_ups_input_module - creates and initialises a new UPS input module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_input_module(void);

/**
 * @internal
 * init_ups_output_module - creates and initialises a new UPS output module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_output_module(void);

/**
 * @internal
 * init_ups_bypass_module - creates and initialises a new UPS bypass module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_bypass_module(void);

/**
 * @internal
 * init_ups_alarm_module - creates and initialises a new UPS alarm module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_alarm_module(void);

/**
 * @internal
 * init_ups_test_module - creates and initialises a new UPS test module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_test_module(void);

/**
 * @internal
 * init_ups_control_module - creates and initialises a new UPS control module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_control_module(void);

/**
 * @internal
 * init_ups_config_module - creates and initialises a new UPS config module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ups_config_module(void);

#endif /* SRC_SNMP_MIB_POWER_UPS_MODULE_H_ */
