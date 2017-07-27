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

#ifndef SRC_SNMP_MIB_IP_IF_INVERTED_MODULE_H_
#define SRC_SNMP_MIB_IP_IF_INVERTED_MODULE_H_

#include "snmp-agent/mib-tree.h"
#include "snmp-mib/mib-module.h"

/* IF-INVERTED-STACK-MIB at 1.3.6.1.2.1.77.1 (RFC 2864) */
#define SNMP_OID_IF_INVERTED SNMP_OID_MIB2,77,1

/**
 * @internal
 * init_inverted_iface_module - creates and initialises a new
 * inverted interface stack module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_inverted_iface_module(void);

#endif /* SRC_SNMP_MIB_IP_IF_INVERTED_MODULE_H_ */
