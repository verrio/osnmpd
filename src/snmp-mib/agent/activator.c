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

#include "snmp-agent/mib-tree.h"
#include "snmp-mib/agent/framework-module.h"
#include "snmp-mib/agent/mpd-stats-module.h"
#include "snmp-mib/agent/notification-module.h"
#include "snmp-mib/agent/snmp-agent-descriptor.h"
#include "snmp-mib/agent/snmp-stats-module.h"
#include "snmp-mib/agent/snmpv2-module.h"
#include "snmp-mib/agent/target-module.h"
#include "snmp-mib/agent/usm-dh-module.h"
#include "snmp-mib/agent/usm-stats-module.h"
#include "snmp-mib/agent/usm-users-module.h"
#include "snmp-mib/agent/ucd-version-module.h"
#include "snmp-mib/agent/vacm-access-module.h"
#include "snmp-mib/agent/vacm-context-module.h"
#include "snmp-mib/agent/vacm-security-group-module.h"
#include "snmp-mib/agent/vacm-views-module.h"

__attribute__((constructor)) static void load_plugin(void)
{
    add_module(init_framework_module, "snmpFrameworkMIB");
    add_module(init_mpd_stats_module, "snmpMPDMIB");
    add_module(init_usm_stats_module, "usmStats");
    add_module(init_usm_users_module, "usmUser");
    add_module(init_usm_dh_module, "usmDH");
    add_module(init_snmpv2_set_module, "snmpSet");
    add_module(init_snmp_stats_module, "snmpGroup");
    add_module(init_notification_module, "snmpNotification");
    add_module(init_target_module, "snmpTarget");
    add_module(init_ucd_version_module, "UCD version");
    add_module(init_vacm_access_module, "vacmAccessTable");
    add_module(init_vacm_context_module, "vacmContextTable");
    add_module(init_vacm_security_group_module, "vacmSecurityToGroupTable");
    add_module(init_vacm_views_module, "vacmMIBViews");
    add_app_module(get_snmp_agent_app_module());

#ifdef DEBUG
    dump_mib_tree();
#endif
}
