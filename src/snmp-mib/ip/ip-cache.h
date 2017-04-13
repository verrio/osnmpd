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

#ifndef SRC_SNMP_MIB_IP_IP_CACHE_H_
#define SRC_SNMP_MIB_IP_IP_CACHE_H_

#define IP_CACHE_UPDATE_INTERVAL 8

#define MAX_ICMP_TYPES  256

#define LOWER_HALF(x) (0xffffffff & (x))

typedef struct {
    uint32_t forwarding;
    uint32_t default_ttl;
    uint64_t in_octets;
    uint64_t out_octets;
    uint64_t in_receives;
    uint64_t in_hdr_errors;
    uint64_t reasm_reqds;
    uint64_t reasm_timeout;
    uint64_t reasm_oks;
    uint64_t reasm_fails;
    uint64_t out_frag_oks;
    uint64_t out_frag_fails;
    uint64_t out_frag_creates;
    uint64_t out_requests;
    uint64_t out_discards;
    uint64_t out_no_routes;
    uint64_t out_forw_datagrams;
    uint64_t out_transmit;
    uint64_t out_routing_discards;
    uint64_t in_discards;
    uint64_t in_delivers;
    uint64_t in_no_routes;
    uint64_t in_addr_errors;
    uint64_t in_unknown_protos;
    uint64_t in_truncated_pkts;
    uint64_t in_forw_datagrams;
    uint64_t in_mcast_pkts;
    uint64_t out_mcast_pkts;
    uint64_t in_mcast_octets;
    uint64_t out_mcast_octets;
    uint64_t in_bcast_pkts;
    uint64_t out_bcast_pkts;
} IpGeneralStatistics;

typedef struct {
    uint64_t in_msg;
    uint64_t in_err;
    uint64_t out_msg;
    uint64_t out_err;
} IcmpStatsTableEntry;

typedef struct {
    uint64_t in_pkts;
    uint64_t out_pkts;
} IcmpMsgStatsTableEntry;

typedef struct {
    IpGeneralStatistics ip4;
    IpGeneralStatistics ip6;
    IcmpStatsTableEntry icmp4;
    IcmpStatsTableEntry icmp6;
    IcmpMsgStatsTableEntry icmp4_msg[MAX_ICMP_TYPES];
    IcmpMsgStatsTableEntry icmp6_msg[MAX_ICMP_TYPES];
} IpStatistics;

/**
 * @internal
 * init_cache - initialise the ip statistics cache
 */
void init_ip_statistics(void);

/**
 * @internal
 * finish_ip_statistics - finalise the ip statistics cache
 */
void finish_ip_statistics(void);

/**
 * @internal
 * get_ip_statistics - returns the current IP statistics
 *
 * @return ip statistics, NULL on error
 */
IpStatistics *get_ip_statistics(void);

#endif /* SRC_SNMP_MIB_IP_IP_CACHE_H_ */
