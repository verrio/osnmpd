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

#define MAX_ICMP_TYPES  256

typedef struct {
    uint32_t in_msg;
    uint32_t in_err;
    uint32_t out_msg;
    uint32_t out_err;
} IcmpStatsTableEntry;

typedef struct {
    uint32_t in_pkts;
    uint32_t out_pkts;
} IcmpMsgStatsTableEntry;

typedef struct {
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
