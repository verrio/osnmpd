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
#include "snmp-mib/power/battery-module.h"
#include "snmp-mib/power/ups-module.h"

__attribute__((constructor)) static void load_plugin(void)
{
    add_module(init_battery_module, "battery");
    add_module(init_ups_ident_module, "UPS ident");
    add_module(init_ups_battery_module, "UPS battery");
    add_module(init_ups_input_module, "UPS input");
    add_module(init_ups_output_module, "UPS output");
    add_module(init_ups_bypass_module, "UPS bypass");
    add_module(init_ups_alarm_module, "UPS alarm");
    add_module(init_ups_test_module, "UPS test");
    add_module(init_ups_control_module, "UPS control");
    add_module(init_ups_config_module, "UPS config");
}
