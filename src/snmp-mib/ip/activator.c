/*
 * This file is part of the osnmpd distribution (https://github.com/verrio/osnmpd).
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
#include "snmp-mib/ip/if-module.h"
#include "snmp-mib/ip/ifx-module.h"
#include "snmp-mib/ip/if-inverted-module.h"
#include "snmp-mib/ip/ip-cache.h"
#include "snmp-mib/ip/ip-module.h"
#include "snmp-mib/ip/icmp-module.h"
#include "snmp-mib/ip/tcp-module.h"
#include "snmp-mib/ip/udp-module.h"

__attribute__((constructor)) static void load_plugin(void)
{
    init_ip_statistics();
    add_module(init_ip_module, "ip");
    add_module(init_icmp_module, "icmp");
    add_module(init_tcp_module, "tcp");
    add_module(init_udp_module, "udp");
    add_module(init_iface_module, "iface");
    add_module(init_ifacex_module, "ifaceX");
    add_module(init_inverted_iface_module, "inverted stack");
}
