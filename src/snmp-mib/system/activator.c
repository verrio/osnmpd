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
#include "snmp-mib/system/application-module.h"
#include "snmp-mib/system/system-module.h"
#include "snmp-mib/system/hr-system-module.h"
#include "snmp-mib/system/hr-storage-module.h"
#include "snmp-mib/system/hr-device-module.h"
#include "snmp-mib/system/hr-sw-run-module.h"
#include "snmp-mib/system/hr-sw-perf-module.h"
#include "snmp-mib/system/hr-sw-installed-module.h"
#include "snmp-mib/system/ucd-module.h"

__attribute__((constructor)) static void load_plugin(void)
{
    add_module(init_system_module, "system");
    add_module(init_hr_system_module, "host system");
    add_module(init_hr_storage_module, "storage");
    add_module(init_hr_device_module, "device");
    add_module(init_hr_sw_run_module, "running software");
    add_module(init_hr_sw_perf_module, "software performance");
    add_module(init_hr_sw_installed_module, "installed software");
    add_module(init_ucd_memory_module, "memory");
    add_module(init_ucd_load_module, "system load");
    add_module(init_ucd_vmstat_module, "vmstat");
    add_module(init_application_module, "applTable");
}
