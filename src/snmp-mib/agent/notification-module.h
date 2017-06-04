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

#ifndef SRC_SNMP_MIB_AGENT_NOTIFICATION_MODULE_H_
#define SRC_SNMP_MIB_AGENT_NOTIFICATION_MODULE_H_

#include "snmp-mib/mib-module.h"

/**
 * SNMP-NOTIFICATION-MIB (RFC 2573), NOTIFICATION-LOG-MIB (RFC 3014)
 * Contains notification related configuration and logging.
 */

#define NOTIFICATION_LOG_MIB_OID    SNMP_OID_MIB2,92

extern const char *const notification_log_name;
extern const char *const notification_filter_name;

/**
 * init_notification_module - creates and initialises a new notification module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_notification_module(void);

/**
 * init_notification_log_module - creates and initialises a new
 * notification log module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_notification_log_module(void);

/**
 * init_notification_log_config_module - creates and initialises a new
 * notification log configuration module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_notification_log_config_module(void);

/**
 * init_notification_log_stats_module - creates and initialises a new
 * notification log statistics module.
 *
 * @return pointer to new module on success, NULL on error.
 */
MibModule *init_notification_log_stats_module(void);

#endif /* SRC_SNMP_MIB_AGENT_NOTIFICATION_MODULE_H_ */
