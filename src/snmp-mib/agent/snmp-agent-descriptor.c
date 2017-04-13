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

#include "config.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-mib/agent/snmp-agent-descriptor.h"

#define AGENT_DESCRIPTION   "SNMPv3 agent"

static char *get_name(void);
static char *get_version(void);
static char *get_description(void);
static ApplicationOperStatus get_oper_state(void);
static uint32_t get_last_inbound(void);
static uint32_t get_last_outbound(void);
static uint32_t get_inbound_assoc(void);
static uint32_t get_acc_inbound_assoc(void);
static uint32_t get_acc_failed_inbound_assoc(void);
static uint32_t get_outbound_assoc(void);
static uint32_t get_acc_outbound_assoc(void);
static uint32_t get_acc_failed_outbound_assoc(void);

static MibApplicationModule app_module = {
    .get_name = get_name,
    .get_version = get_version,
    .get_description = get_description,
    .get_oper_state = get_oper_state,
    .get_uptime = get_uptime,
    .get_last_change = get_uptime,
    .get_last_inbound = get_last_inbound,
    .get_last_outbound = get_last_outbound,
    .get_inbound_assoc = get_inbound_assoc,
    .get_acc_inbound_assoc = get_acc_inbound_assoc,
    .get_acc_failed_inbound_assoc = get_acc_failed_inbound_assoc,
    .get_outbound_assoc = get_outbound_assoc,
    .get_acc_outbound_assoc = get_acc_outbound_assoc,
    .get_acc_failed_outbound_assoc = get_acc_failed_outbound_assoc,
    .next = NULL
};

MibApplicationModule *get_snmp_agent_app_module(void)
{
    return &app_module;
}

static char *get_name(void)
{
    return PACKAGE_NAME;
}

static char *get_version(void)
{
    return VERSION;
}

static char *get_description(void)
{
    return AGENT_DESCRIPTION;
}

static ApplicationOperStatus get_oper_state(void)
{
    return NET_APP_UP;
}

static uint32_t get_last_inbound(void)
{
    return 0;

}

static uint32_t get_last_outbound(void)
{
    return get_statistics()->last_outbound_timestamp;
}

static uint32_t get_inbound_assoc(void)
{
    return 0;
}

static uint32_t get_acc_inbound_assoc(void)
{
    return 0;
}

static uint32_t get_acc_failed_inbound_assoc(void)
{
    return 0;
}

static uint32_t get_outbound_assoc(void)
{
    return 0;
}

static uint32_t get_acc_outbound_assoc(void)
{
    return 0;
}

static uint32_t get_acc_failed_outbound_assoc(void)
{
    return 0;
}
