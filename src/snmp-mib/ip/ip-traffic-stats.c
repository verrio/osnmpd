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

#include <sys/utsname.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/ip/if-cache.h"
#include "snmp-mib/ip/ip-cache.h"
#include "snmp-mib/ip/ip-address-cache.h"
#include "snmp-mib/ip/ip-module.h"
#include "snmp-mib/ip/ip-traffic-stats.h"

enum IPTrafficStatsMIB {
    IP_SYSTEM_STATS_TABLE = 1,
    IP_IF_STATS_TABLE_LAST_CHANGE = 2,
    IP_IF_STATS_TABLE = 3
};

enum IPSystemStatsTableColumns {
    IP_SYSTEM_STATS_IP_VERSION = 1,
    IP_SYSTEM_STATS_UNUSED = 2,
    IP_SYSTEM_STATS_IN_RECEIVES = 3,
    IP_SYSTEM_STATS_HC_IN_RECEIVES = 4,
    IP_SYSTEM_STATS_IN_OCTETS = 5,
    IP_SYSTEM_STATS_HC_IN_OCTETS = 6,
    IP_SYSTEM_STATS_IN_HDR_ERRORS = 7,
    IP_SYSTEM_STATS_IN_NO_ROUTES = 8,
    IP_SYSTEM_STATS_IN_ADDR_ERRORS = 9,
    IP_SYSTEM_STATS_IN_UNKNOWN_PROTOS = 10,
    IP_SYSTEM_STATS_IN_TRUNCATED_PKTS = 11,
    IP_SYSTEM_STATS_IN_FORW_DATAGRAMS = 12,
    IP_SYSTEM_STATS_HC_IN_FORW_DATAGRAMS = 13,
    IP_SYSTEM_STATS_REASM_REQDS = 14,
    IP_SYSTEM_STATS_REASM_OKS = 15,
    IP_SYSTEM_STATS_REASM_FAILS = 16,
    IP_SYSTEM_STATS_IN_DISCARDS = 17,
    IP_SYSTEM_STATS_IN_DELIVERS = 18,
    IP_SYSTEM_STATS_HC_IN_DELIVERS = 19,
    IP_SYSTEM_STATS_OUT_REQUESTS = 20,
    IP_SYSTEM_STATS_HC_OUT_REQUESTS = 21,
    IP_SYSTEM_STATS_OUT_NO_ROUTES = 22,
    IP_SYSTEM_STATS_OUT_FORW_DATAGRAMS = 23,
    IP_SYSTEM_STATS_HC_OUT_FORW_DATAGRAMS = 24,
    IP_SYSTEM_STATS_OUT_DISCARDS = 25,
    IP_SYSTEM_STATS_OUT_FRAG_REQDS = 26,
    IP_SYSTEM_STATS_OUT_FRAG_OKS = 27,
    IP_SYSTEM_STATS_OUT_FRAG_FAILS = 28,
    IP_SYSTEM_STATS_OUT_FRAG_CREATES = 29,
    IP_SYSTEM_STATS_OUT_TRANSMITS = 30,
    IP_SYSTEM_STATS_HC_OUT_TRANSMITS = 31,
    IP_SYSTEM_STATS_OUT_OCTETS = 32,
    IP_SYSTEM_STATS_HC_OUT_OCTETS = 33,
    IP_SYSTEM_STATS_IN_MCAST_PKTS = 34,
    IP_SYSTEM_STATS_HC_IN_MCAST_PKTS = 35,
    IP_SYSTEM_STATS_IN_MCAST_OCTETS = 36,
    IP_SYSTEM_STATS_HC_IN_MCAST_OCTETS = 37,
    IP_SYSTEM_STATS_OUT_MCAST_PKTS = 38,
    IP_SYSTEM_STATS_HC_OUT_MCAST_PKTS = 39,
    IP_SYSTEM_STATS_OUT_MCAST_OCTETS = 40,
    IP_SYSTEM_STATS_HC_OUT_MCAST_OCTETS = 41,
    IP_SYSTEM_STATS_IN_BCAST_PKTS = 42,
    IP_SYSTEM_STATS_HC_IN_BCAST_PKTS = 43,
    IP_SYSTEM_STATS_OUT_BCAST_PKTS = 44,
    IP_SYSTEM_STATS_HC_OUT_BCAST_PKTS = 45,
    IP_SYSTEM_STATS_DISCONTINUITY_TIME = 46,
    IP_SYSTEM_STATS_REFRESH_RATE = 47
};

enum IPIFStatusTableColumns {
    IP_IF_STATS_IP_VERSION = 1,
    IP_IF_STATS_IF_INDEX = 2,
    IP_IF_STATS_IN_RECEIVES = 3,
    IP_IF_STATS_HC_IN_RECEIVES = 4,
    IP_IF_STATS_IN_OCTETS = 5,
    IP_IF_STATS_HC_IN_OCTETS = 6,
    IP_IF_STATS_IN_HDR_ERRORS = 7,
    IP_IF_STATS_IN_NO_ROUTES = 8,
    IP_IF_STATS_IN_ADDR_ERRORS = 9,
    IP_IF_STATS_IN_UNKNOWN_PROTOS = 10,
    IP_IF_STATS_IN_TRUNCATED_PKTS = 11,
    IP_IF_STATS_IN_FORW_DATAGRAMS = 12,
    IP_IF_STATS_HC_IN_FORW_DATAGRAMS = 13,
    IP_IF_STATS_REASM_REQDS = 14,
    IP_IF_STATS_REASM_OKS = 15,
    IP_IF_STATS_REASM_FAILS = 16,
    IP_IF_STATS_IN_DISCARDS = 17,
    IP_IF_STATS_IN_DELIVERS = 18,
    IP_IF_STATS_HC_IN_DELIVERS = 19,
    IP_IF_STATS_OUT_REQUESTS = 20,
    IP_IF_STATS_HC_OUT_REQUESTS = 21,
    IP_IF_STATS_UNUSED = 22,
    IP_IF_STATS_OUT_FORW_DATAGRAMS = 23,
    IP_IF_STATS_HC_OUT_FORW_DATAGRAMS = 24,
    IP_IF_STATS_OUT_DISCARDS = 25,
    IP_IF_STATS_OUT_FRAG_REQDS = 26,
    IP_IF_STATS_OUT_FRAG_OKS = 27,
    IP_IF_STATS_OUT_FRAG_FAILS = 28,
    IP_IF_STATS_OUT_FRAG_CREATES = 29,
    IP_IF_STATS_OUT_TRANSMITS = 30,
    IP_IF_STATS_HC_OUT_TRANSMITS = 31,
    IP_IF_STATS_OUT_OCTETS = 32,
    IP_IF_STATS_HC_OUT_OCTETS = 33,
    IP_IF_STATS_IN_MCAST_PKTS = 34,
    IP_IF_STATS_HC_IN_MCAST_PKTS = 35,
    IP_IF_STATS_IN_MCAST_OCTETS = 36,
    IP_IF_STATS_HC_IN_MCAST_OCTETS = 37,
    IP_IF_STATS_OUT_MCAST_PKTS = 38,
    IP_IF_STATS_HC_OUT_MCAST_PKTS = 39,
    IP_IF_STATS_OUT_MCAST_OCTETS = 40,
    IP_IF_STATS_HC_OUT_MCAST_OCTETS = 41,
    IP_IF_STATS_IN_BCAST_PKTS = 42,
    IP_IF_STATS_HC_IN_BCAST_PKTS = 43,
    IP_IF_STATS_OUT_BCAST_PKTS = 44,
    IP_IF_STATS_HC_OUT_BCAST_PKTS = 45,
    IP_IF_STATS_DISCONTINUITY_TIME = 46,
    IP_IF_STATS_REFRESH_RATE = 47
};

static enum IpAddressFamily get_ip_version(SubOID *row, size_t row_len, int next_row)
{
    if (!next_row) {
        if (row_len == 1 && (row[0] == ADDRESS_IP4 || row[0] == ADDRESS_IP6)) {
            return row[0];
        }
    } else if (row_len < 1 || row[0] < ADDRESS_IP4) {
        return ADDRESS_IP4;
    } else if (row[0] < ADDRESS_IP6) {
        return ADDRESS_IP6;
    }

    return ADDRESS_UNKNOWN;
}

static IfaceEntry *get_iface_entry(SubOID *row, size_t row_len, int next_row)
{
    int iface;

    if (next_row) {
        if (row_len < 1 || row[0] < ADDRESS_IP6) {
            iface = 0;
        } else if (row[0] == ADDRESS_IP6) {
            iface = row_len > 1 ? row[1] : 0;
        } else {
            return NULL;
        }
    } else if (row_len != 2 || row[0] != ADDRESS_IP6) {
        return NULL;
    } else {
        iface = row[1];
    }

    for (IfaceEntry *entry = get_iface_list(); entry != NULL; entry = entry->next) {
        if (iface < entry->id) {
            return next_row ? entry : NULL;
        } else if (!next_row && iface == entry->id) {
            return entry;
        }
    }

    return NULL;
}

static SnmpErrorStatus get_ip_system_stats_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    IpStatistics *statistics = get_ip_statistics();
    if (statistics == NULL) {
        return GENERAL_ERROR;
    }

    enum IpAddressFamily version = get_ip_version(row, row_len, next_row);
    IpGeneralStatistics *ip_stats = NULL;
    if (version == ADDRESS_IP4) {
        ip_stats = &statistics->ip4;
    } else if (version == ADDRESS_IP6) {
        ip_stats = &statistics->ip6;
    }
    CHECK_INSTANCE_FOUND(next_row, ip_stats);

    switch (column) {
        case IP_SYSTEM_STATS_IP_VERSION: {
            SET_INTEGER_BIND(binding, version);
            break;
        }

        case IP_SYSTEM_STATS_UNUSED: {
            binding->type = SMI_TYPE_NULL;
            break;
        }

        case IP_SYSTEM_STATS_IN_RECEIVES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_receives));
            break;
        }

        case IP_SYSTEM_STATS_HC_IN_RECEIVES: {
            SET_UNSIGNED64_BIND(binding, ip_stats->in_receives);
            break;
        }

        case IP_SYSTEM_STATS_IN_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_octets));
            break;
        }

        case IP_SYSTEM_STATS_HC_IN_OCTETS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->in_octets);
            break;
        }

        case IP_SYSTEM_STATS_IN_HDR_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_hdr_errors));
            break;
        }

        case IP_SYSTEM_STATS_IN_NO_ROUTES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_no_routes));
            break;
        }

        case IP_SYSTEM_STATS_IN_ADDR_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_addr_errors));
            break;
        }

        case IP_SYSTEM_STATS_IN_UNKNOWN_PROTOS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_unknown_protos));
            break;
        }

        case IP_SYSTEM_STATS_IN_TRUNCATED_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_truncated_pkts));
            break;
        }

        case IP_SYSTEM_STATS_IN_FORW_DATAGRAMS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_forw_datagrams));
            break;
        }

        case IP_SYSTEM_STATS_HC_IN_FORW_DATAGRAMS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->in_forw_datagrams);
            break;
        }

        case IP_SYSTEM_STATS_REASM_REQDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->reasm_reqds));
            break;
        }

        case IP_SYSTEM_STATS_REASM_OKS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->reasm_oks));
            break;
        }

        case IP_SYSTEM_STATS_REASM_FAILS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->reasm_fails));
            break;
        }

        case IP_SYSTEM_STATS_IN_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_discards));
            break;
        }

        case IP_SYSTEM_STATS_IN_DELIVERS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_delivers));
            break;
        }

        case IP_SYSTEM_STATS_HC_IN_DELIVERS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->in_delivers);
            break;
        }

        case IP_SYSTEM_STATS_OUT_REQUESTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_requests));
            break;
        }

        case IP_SYSTEM_STATS_HC_OUT_REQUESTS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->out_requests);
            break;
        }

        case IP_SYSTEM_STATS_OUT_NO_ROUTES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_no_routes));
            break;
        }

        case IP_SYSTEM_STATS_OUT_FORW_DATAGRAMS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_forw_datagrams));
            break;
        }

        case IP_SYSTEM_STATS_HC_OUT_FORW_DATAGRAMS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->out_forw_datagrams);
            break;
        }

        case IP_SYSTEM_STATS_OUT_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_discards));
            break;
        }

        case IP_SYSTEM_STATS_OUT_FRAG_REQDS: {
            SET_UNSIGNED_BIND(binding,
                LOWER_HALF(ip_stats->out_frag_oks + ip_stats->out_frag_fails));
            break;
        }

        case IP_SYSTEM_STATS_OUT_FRAG_OKS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_frag_oks));
            break;
        }

        case IP_SYSTEM_STATS_OUT_FRAG_FAILS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_frag_fails));
            break;
        }

        case IP_SYSTEM_STATS_OUT_FRAG_CREATES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_frag_creates));
            break;
        }

        case IP_SYSTEM_STATS_OUT_TRANSMITS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_transmit));
            break;
        }

        case IP_SYSTEM_STATS_HC_OUT_TRANSMITS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->out_transmit);
            break;
        }

        case IP_SYSTEM_STATS_OUT_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_octets));
            break;
        }

        case IP_SYSTEM_STATS_HC_OUT_OCTETS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->out_octets);
            break;
        }

        case IP_SYSTEM_STATS_IN_MCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_mcast_pkts));
            break;
        }

        case IP_SYSTEM_STATS_HC_IN_MCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->in_mcast_pkts);
            break;
        }

        case IP_SYSTEM_STATS_IN_MCAST_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_mcast_octets));
            break;
        }

        case IP_SYSTEM_STATS_HC_IN_MCAST_OCTETS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->in_mcast_octets);
            break;
        }

        case IP_SYSTEM_STATS_OUT_MCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_mcast_pkts));
            break;
        }

        case IP_SYSTEM_STATS_HC_OUT_MCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->out_mcast_pkts);
            break;
        }

        case IP_SYSTEM_STATS_OUT_MCAST_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_mcast_octets));
            break;
        }

        case IP_SYSTEM_STATS_HC_OUT_MCAST_OCTETS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->out_mcast_octets);
            break;
        }

        case IP_SYSTEM_STATS_IN_BCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->in_bcast_pkts));
            break;
        }

        case IP_SYSTEM_STATS_HC_IN_BCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->in_bcast_pkts);
            break;
        }

        case IP_SYSTEM_STATS_OUT_BCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->out_bcast_pkts));
            break;
        }

        case IP_SYSTEM_STATS_HC_OUT_BCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, ip_stats->out_bcast_pkts);
            break;
        }

        case IP_SYSTEM_STATS_DISCONTINUITY_TIME: {
            SET_TIME_TICKS_BIND(binding, 0);
            break;
        }

        case IP_SYSTEM_STATS_REFRESH_RATE: {
            SET_GAUGE_BIND(binding, IP_CACHE_UPDATE_INTERVAL * 1000);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_IP_TRAFFIC_STATS,
        IP_SYSTEM_STATS_TABLE, column, version)
}

static SnmpErrorStatus get_if_stats_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    IfaceEntry *iface = get_iface_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, iface);

    switch (column) {
        case IP_IF_STATS_IP_VERSION: {
            SET_INTEGER_BIND(binding, ADDRESS_IP6);
            break;
        }

        case IP_IF_STATS_IF_INDEX: {
            SET_INTEGER_BIND(binding, iface->id);
            break;
        }

        case IP_IF_STATS_IN_RECEIVES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_receives));
            break;
        }

        case IP_IF_STATS_HC_IN_RECEIVES: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.in_receives);
            break;
        }

        case IP_IF_STATS_IN_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_octets));
            break;
        }

        case IP_IF_STATS_HC_IN_OCTETS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.in_octets);
            break;
        }

        case IP_IF_STATS_IN_HDR_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_hdr_errors));
            break;
        }

        case IP_IF_STATS_IN_NO_ROUTES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_no_routes));
            break;
        }

        case IP_IF_STATS_IN_ADDR_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_addr_errors));
            break;
        }

        case IP_IF_STATS_IN_UNKNOWN_PROTOS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_unknown_protos));
            break;
        }

        case IP_IF_STATS_IN_TRUNCATED_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_truncated_pkts));
            break;
        }

        case IP_IF_STATS_IN_FORW_DATAGRAMS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_forw_datgrams));
            break;
        }

        case IP_IF_STATS_HC_IN_FORW_DATAGRAMS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.in_forw_datgrams);
            break;
        }

        case IP_IF_STATS_REASM_REQDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.reasm_reqds));
            break;
        }

        case IP_IF_STATS_REASM_OKS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.reasm_ok));
            break;
        }

        case IP_IF_STATS_REASM_FAILS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.reasm_fails));
            break;
        }

        case IP_IF_STATS_IN_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_discards));
            break;
        }

        case IP_IF_STATS_IN_DELIVERS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.in_delivers));
            break;
        }

        case IP_IF_STATS_HC_IN_DELIVERS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.in_delivers);
            break;
        }

        case IP_IF_STATS_OUT_REQUESTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_requests));
            break;
        }

        case IP_IF_STATS_HC_OUT_REQUESTS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.out_requests);
            break;
        }

        case IP_IF_STATS_UNUSED: {
            binding->type = SMI_TYPE_NULL;
            break;
        }

        case IP_IF_STATS_OUT_FORW_DATAGRAMS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_forw_datagrams));
            break;
        }

        case IP_IF_STATS_HC_OUT_FORW_DATAGRAMS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.out_forw_datagrams);
            break;
        }

        case IP_IF_STATS_OUT_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_discards));
            break;
        }

        case IP_IF_STATS_OUT_FRAG_REQDS: {
            SET_UNSIGNED_BIND(binding,
                LOWER_HALF(iface->ip6_stats.out_frag_oks + iface->ip6_stats.out_frag_fails));
            break;
        }

        case IP_IF_STATS_OUT_FRAG_OKS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_frag_oks));
            break;
        }

        case IP_IF_STATS_OUT_FRAG_FAILS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_frag_fails));
            break;
        }

        case IP_IF_STATS_OUT_FRAG_CREATES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_frag_creates));
            break;
        }

        case IP_IF_STATS_OUT_TRANSMITS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_transmits));
            break;
        }

        case IP_IF_STATS_HC_OUT_TRANSMITS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.out_transmits);
            break;
        }

        case IP_IF_STATS_OUT_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_octets));
            break;
        }

        case IP_IF_STATS_HC_OUT_OCTETS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.out_octets);
            break;
        }

        case IP_IF_STATS_IN_MCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_mcast_pkts));
            break;
        }

        case IP_IF_STATS_HC_IN_MCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.out_mcast_pkts);
            break;
        }

        case IP_IF_STATS_IN_MCAST_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_mcast_pkts));
            break;
        }

        case IP_IF_STATS_HC_IN_MCAST_OCTETS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.in_mcast_octets);
            break;
        }

        case IP_IF_STATS_OUT_MCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_mcast_pkts));
            break;
        }

        case IP_IF_STATS_HC_OUT_MCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.out_mcast_pkts);
            break;
        }

        case IP_IF_STATS_OUT_MCAST_OCTETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(iface->ip6_stats.out_mcast_octets));
            break;
        }

        case IP_IF_STATS_HC_OUT_MCAST_OCTETS: {
            SET_UNSIGNED64_BIND(binding, iface->ip6_stats.out_mcast_octets);
            break;
        }

        case IP_IF_STATS_IN_BCAST_PKTS:
        case IP_IF_STATS_OUT_BCAST_PKTS: {
            SET_UNSIGNED_BIND(binding, 0);
            break;
        }

        case IP_IF_STATS_HC_IN_BCAST_PKTS:
        case IP_IF_STATS_HC_OUT_BCAST_PKTS: {
            SET_UNSIGNED64_BIND(binding, 0);
            break;
        }

        case IP_IF_STATS_DISCONTINUITY_TIME: {
            SET_TIME_TICKS_BIND(binding, 0);
            break;
        }

        case IP_IF_STATS_REFRESH_RATE: {
            SET_GAUGE_BIND(binding, IP_CACHE_UPDATE_INTERVAL * 1000);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW2(next_row, SNMP_OID_IP_TRAFFIC_STATS,
            IP_IF_STATS_TABLE, column, ADDRESS_IP6, iface->id)
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    SET_TIME_TICKS_BIND(binding, 0);
    return NO_ERROR;
}

DEF_METHOD(set_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    switch (id) {
        case IP_SYSTEM_STATS_TABLE: {
            return get_ip_system_stats_table(column, row, row_len, binding, next_row);
        }

        case IP_IF_STATS_TABLE: {
            return get_if_stats_table(column, row, row_len, binding, next_row);
        }

        default: {
            return GENERAL_ERROR;
        }
    }
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *index, size_t index_len,
    SnmpVariableBinding *binding, int dry_run)
{
    return NO_CREATION;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_ip_traffic_stats_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, IP_SYSTEM_STATS_TABLE,
            IP_IF_STATS_TABLE - IP_SYSTEM_STATS_TABLE + 1,
            IP_SYSTEM_STATS_REFRESH_RATE, LEAF_SCALAR, IP_IF_STATS_REFRESH_RATE)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_IP_TRAFFIC_STATS);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
