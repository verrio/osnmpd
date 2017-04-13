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

#ifndef SRC_SNMP_MIB_SYSTEM_UCD_MODULE_H_
#define SRC_SNMP_MIB_SYSTEM_UCD_MODULE_H_

#include "snmp-mib/mib-module.h"

/*
 * modules relating to the ucdavis UCD-SNMP-MIB at .1.3.6.1.4.1.2021
 * only selective parts of this MIB are available.
 */
#define SNMP_OID_UCD    SNMP_OID_ENTERPRISES,2021
#define SNMP_OID_UCD_MEM    SNMP_OID_UCD,4
#define SNMP_OID_UCD_LOAD_TABLE 10
#define SNMP_OID_UCD_LOAD   SNMP_OID_UCD,SNMP_OID_UCD_LOAD_TABLE
#define SNMP_OID_UCD_CPU    SNMP_OID_UCD,11

/**
 * @internal
 * init_ucd_memory_module - creates and initialises a new UCD memory module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ucd_memory_module(void);

/**
 * @internal
 * init_ucd_load_module - creates and initialises a new UCD load module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ucd_load_module(void);

/**
 * @internal
 * init_ucd_vmstat_module - creates and initialises a new UCD VM statistics module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_ucd_vmstat_module(void);

#endif /* SRC_SNMP_MIB_SYSTEM_UCD_MODULE_H_ */
