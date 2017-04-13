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

#ifndef SRC_SNMP_MIB_SYSTEM_HR_DEVICE_MODULE_H_
#define SRC_SNMP_MIB_SYSTEM_HR_DEVICE_MODULE_H_

#include "snmp-agent/mib-tree.h"
#include "snmp-mib/mib-module.h"

/* device group of HOST-RESOURCES-MIB at .1.3.6.1.2.1.25.3 (RFC 2790) */
#define SNMP_OID_HR_DEVICE SNMP_OID_MIB2,25,3

/**
 * @internal
 * init_hr_device_module - creates and initialises a new device module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_hr_device_module(void);

#endif /* SRC_SNMP_MIB_SYSTEM_HR_DEVICE_MODULE_H_ */
