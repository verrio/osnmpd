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

#ifndef SRC_SNMP_MIB_IP_SCTP_H_
#define SRC_SNMP_MIB_IP_SCTP_H_

/* SCTP-MIB at 1.3.6.1.2.1.104 (RFC 3873) */
#define SNMP_OID_SCTP           SNMP_OID_MIB2,104
#define SNMP_OID_SCTP_OBJECTS   SNMP_OID_SCTP,1

/**
 * @internal
 * init_sctp_stats_module - creates and initialises
 * a new SCTP statistics module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_stats_module(void);

/**
 * @internal
 * init_sctp_params_module - creates and initialises
 * a new SCTP parameters module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_params_module(void);

/**
 * @internal
 * init_sctp_assoc_module - creates and initialises
 * a new association SCTP module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_assoc_module(void);

/**
 * @internal
 * init_sctp_assoc_local_module - creates and initialises
 * a new local association SCTP module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_assoc_local_module(void);

/**
 * @internal
 * init_sctp_assoc_remote_module - creates and initialises
 * a new remote association SCTP module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_assoc_remote_module(void);

/**
 * @internal
 * init_sctp_local_port_module - creates and initialises
 * a new local port SCTP module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_local_port_module(void);

/**
 * @internal
 * init_sctp_remote_port_module - creates and initialises
 * a new remote port SCTP module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_remote_port_module(void);

/**
 * @internal
 * init_sctp_hostname_module - creates and initialises
 * a new hostname SCTP module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_hostname_module(void);

/**
 * @internal
 * init_sctp_primary_ip_module - creates and initialises
 * a new primary IP SCTP module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_primary_ip_module(void);

/**
 * @internal
 * init_sctp_remote_ip_module - creates and initialises
 * a new SCTP remote ip module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_sctp_remote_ip_module(void);

#endif /* SRC_SNMP_MIB_IP_SCTP_H_ */
