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

#include <sys/sysinfo.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#include "snmp-core/utils.h"
#include "snmp-mib/ip/ip-cache.h"

#define IP4_STATS_LINE "Ip: %"PRIu32" %"PRIu32" %"PRIu64" %"PRIu64" %"PRIu64 \
    " %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64 \
    " %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64
#define IP6_STATS_LINE "Ip6%*s %"PRIu64
#define ICMP4_STATS_LINE "Icmp: %"PRIu64" %"PRIu64" %*u %*u %*u %*u %*u %*u" \
    "%*u %*u %*u %*u %*u %"PRIu64" %"PRIu64" %*u %*u %*u %*u %*u %*u %*u %*u" \
    " %*u %*u %*u"
#define ICMP4_MSG_STATS_PREFIX "IcmpMsg: "
#define ICMP4_MSG_IN    "InType%"PRIu8
#define ICMP4_MSG_OUT    "OutType%"PRIu8
#define ICMP6_IN_MSG    "Icmp6InMsgs%*64[ \t]%"PRIu64
#define ICMP6_IN_ERR    "Icmp6InErrors%*64[ \t]%"PRIu64
#define ICMP6_OUT_MSG    "Icmp6OutMsgs%*64[ \t]%"PRIu64
#define ICMP6_OUT_ERR    "Icmp6OutErrors%*64[ \t]%"PRIu64
#define ICMP6_IN_TYPE    "Icmp6InType%"PRIu8"%*64[ \t]%"PRIu64
#define ICMP6_OUT_TYPE    "Icmp6OutType%"PRIu8"%*64[ \t]%"PRIu64

#define READ_NEXT(match, result) do { \
    if (line != fgets(line, sizeof(line), f) ||  \
        sscanf(line, match, result) != 1) {  \
        ret = -1; \
        goto end; \
    } \
} while (0);

#define VALIDATE_ICMP_TYPE(val) do { \
    if (type >= MAX_ICMP_TYPES) { \
        return -1; \
    } \
} while (0);

static const char *ip4_snmp = "/proc/net/snmp";
static const char *ip6_snmp = "/proc/net/snmp6";
static const char *ip6_forwarding = "/proc/sys/net/ipv6/conf/all/forwarding";
static const char *ip6_ttl = "/proc/sys/net/ipv6/conf/all/hop_limit";

static uint32_t last_update;
static IpStatistics ip_statistics;

static int read_ip4_stats(void);
static int read_ip4_icmp_msg(char *, char *);
static int read_ip6_stats(void);
static int skip_till_prefix(FILE *, char *, size_t, char *);

void init_ip_statistics(void)
{
    last_update = UINT32_MAX;
    memset(&ip_statistics, 0, sizeof(IpStatistics));
}

void finish_ip_statistics(void)
{
    /* NOP */
}

IpStatistics *get_ip_statistics(void)
{
    struct sysinfo s_info;
    if (sysinfo(&s_info)) {
        return NULL;
    }

    if ((uint32_t) s_info.uptime - last_update < IP_CACHE_UPDATE_INTERVAL) {
        return &ip_statistics;
    }

    if (read_ip4_stats()) {
        syslog(LOG_ERR, "failed to fetch ipv4 statistics.");
        return NULL;
    } else if (read_ip6_stats()) {
        syslog(LOG_ERR, "failed to fetch ipv6 statistics.");
        return NULL;
    }

    last_update = s_info.uptime;
    return &ip_statistics;
}

static int read_ip4_stats(void)
{
    int ret = 0;
    FILE *f = NULL;
    if ((f = fopen(ip4_snmp, "r")) == NULL) {
        syslog(LOG_ERR, "failed to open %s : %s", ip4_snmp, strerror(errno));
        ret = -1;
        goto end;
    }

    char line[1024];
    int found_ip = 0;
    int found_icmp = 0;
    int found_icmp_msg = 0;

    while (!(found_ip && found_icmp && found_icmp_msg) &&
            (line == fgets(line, sizeof(line), f))) {
        if (!found_ip && sscanf(line, IP4_STATS_LINE,
            &ip_statistics.ip4.forwarding, &ip_statistics.ip4.default_ttl,
            &ip_statistics.ip4.in_receives, &ip_statistics.ip4.in_hdr_errors,
            &ip_statistics.ip4.in_addr_errors, &ip_statistics.ip4.in_forw_datagrams,
            &ip_statistics.ip4.in_unknown_protos, &ip_statistics.ip4.in_discards,
            &ip_statistics.ip4.in_delivers, &ip_statistics.ip4.out_requests,
            &ip_statistics.ip4.out_discards, &ip_statistics.ip4.out_no_routes,
            &ip_statistics.ip4.reasm_timeout, &ip_statistics.ip4.reasm_reqds,
            &ip_statistics.ip4.reasm_oks, &ip_statistics.ip4.reasm_fails,
            &ip_statistics.ip4.out_frag_oks, &ip_statistics.ip4.out_frag_fails,
            &ip_statistics.ip4.out_frag_creates) == 19) {
            ip_statistics.ip4.out_routing_discards = 0;
            if (!ip_statistics.ip4.forwarding)
                ip_statistics.ip4.forwarding = 2;
            found_ip = 1;
        } else if (!found_icmp && sscanf(line, ICMP4_STATS_LINE,
            &ip_statistics.icmp4.in_msg, &ip_statistics.icmp4.in_err,
            &ip_statistics.icmp4.out_msg, &ip_statistics.icmp4.out_err) == 4) {
            found_icmp = 1;
        } else if (!found_icmp_msg && !strncmp(line,
                ICMP4_MSG_STATS_PREFIX, strlen(ICMP4_MSG_STATS_PREFIX))) {
            char values[1024];
            if (fgets(values, sizeof(values), f) != values) {
                ret = -1;
                goto end;
            } else if (read_ip4_icmp_msg(line + strlen(ICMP4_MSG_STATS_PREFIX),
                values + strlen(ICMP4_MSG_STATS_PREFIX))) {
                ret = -1;
                goto end;
            }
            found_icmp_msg = 1;
        }
    }

    ret = !(found_ip && found_icmp && found_icmp_msg);
end:
    if (f != NULL) {
        fclose(f);
    }
    return ret;
}

static int read_ip4_icmp_msg(char *header, char *values)
{
    char *save_head = header;
    char *save_val = values;

    char *tok_head;
    while ((tok_head = strtok_r(save_head, " ", &save_head)) != NULL) {
        char *tok_val = strtok_r(save_val, " ", &save_val);
        if (tok_val == NULL) {
            return -1;
        }

        uint32_t type;
        if (sscanf(tok_head, ICMP4_MSG_IN, &type) == 1) {
            VALIDATE_ICMP_TYPE(type);
            ip_statistics.icmp4_msg[type].in_pkts = strtol(tok_val, NULL, 10);
        } else if (sscanf(tok_head, ICMP4_MSG_OUT, &type) == 1) {
            VALIDATE_ICMP_TYPE(type);
            ip_statistics.icmp4_msg[type].out_pkts = strtol(tok_val, NULL, 10);
        } else {
            return -1;
        }
    }

    return 0;
}

static int read_ip6_stats(void)
{
    int ret = 0;

    if (read_unsigned_from_file(ip6_forwarding, &ip_statistics.ip6.forwarding)) {
        return -1;
    } else if (read_unsigned_from_file(ip6_ttl, &ip_statistics.ip6.default_ttl)) {
        return -1;
    }
    if (!ip_statistics.ip6.forwarding) {
        ip_statistics.ip6.forwarding = 2;
    }

    FILE *f = NULL;
    if ((f = fopen(ip6_snmp, "r")) == NULL) {
        syslog(LOG_ERR, "failed to open %s : %s", ip6_snmp, strerror(errno));
        ret = -1;
        goto end;
    }

    char line[1024];
    line[0] = '\0';

    while (line == fgets(line, sizeof(line), f)) {
        uint64_t val;
        if (sscanf(line, IP6_STATS_LINE, &val) != 1) {
            break;
        }
        if (!strncmp(line + 3, "In", 2)) {
            if (!strcmp(line + 5, "AddrErrors")) {
                ip_statistics.ip6.in_addr_errors = val;
            } else if (!strcmp(line + 5, "Delivers")) {
                ip_statistics.ip6.in_delivers = val;
            } else if (!strcmp(line + 5, "Discards")) {
                ip_statistics.ip6.in_discards = val;
            } else if (!strcmp(line + 5, "HdrErrors")) {
                ip_statistics.ip6.in_hdr_errors = val;
            } else if (!strcmp(line + 5, "McastPkts")) {
                ip_statistics.ip6.in_mcast_pkts = val;
            } else if (!strcmp(line + 5, "NoRoutes")) {
                ip_statistics.ip6.in_no_routes = val;
            } else if (!strcmp(line + 5, "Receives")) {
                ip_statistics.ip6.in_receives = val;
            } else if (!strcmp(line + 5, "TruncatedPkts")) {
                ip_statistics.ip6.in_truncated_pkts = val;
            } else if (!strcmp(line + 5, "UnknownProtos")) {
                ip_statistics.ip6.in_unknown_protos = val;
            } else if (!strcmp(line + 5, "Octets")) {
                ip_statistics.ip6.in_octets = val;
            } else if (!strcmp(line + 5, "McastOctets")) {
                ip_statistics.ip6.in_mcast_octets = val;
            }
        } else if (!strncmp(line + 3, "Out", 3)) {
            if (!strcmp(line + 6, "Discards")) {
                ip_statistics.ip6.out_discards = val;
            } else if (!strcmp(line + 6, "ForwDatagrams")) {
                ip_statistics.ip6.out_forw_datagrams = val;
            } else if (!strcmp(line + 6, "McastPkts")) {
                ip_statistics.ip6.out_mcast_pkts = val;
            } else if (!strcmp(line + 6, "NoRoutes")) {
                ip_statistics.ip6.out_no_routes = val;
            } else if (!strcmp(line + 6, "Requests")) {
                ip_statistics.ip6.out_requests = val;
            } else if (!strcmp(line + 6, "Octets")) {
                ip_statistics.ip6.out_octets = val;
            } else if (!strcmp(line + 6, "McastOctets")) {
                ip_statistics.ip6.out_mcast_octets = val;
            }
        } else if (!strncmp(line + 3, "Reasm", 5)) {
            if (!strcmp(line + 8, "Fails")) {
                ip_statistics.ip6.reasm_fails = val;
            } else if (!strcmp(line + 8, "OKs")) {
                ip_statistics.ip6.reasm_oks = val;
            } else if (!strcmp(line + 8, "Reqds")) {
                ip_statistics.ip6.reasm_reqds = val;
            } else if (!strcmp(line + 8, "Timeout")) {
                ip_statistics.ip6.reasm_timeout = val;
            }
        } else if (!strncmp(line + 3, "Frag", 4)) {
            if (!strcmp(line + 7, "Creates")) {
                ip_statistics.ip6.out_frag_creates = val;
            } else if (!strcmp(line + 7, "Fails")) {
                ip_statistics.ip6.out_frag_fails = val;
            } else if (!strcmp(line + 7, "OKs")) {
                ip_statistics.ip6.out_frag_oks = val;
            }
        }
    }

    if (skip_till_prefix(f, line, sizeof(line), "Icmp")) {
        ret = -1;
        goto end;
    } else if (sscanf(line, ICMP6_IN_MSG, &ip_statistics.icmp6.in_msg) != 1) {
        ret = -1;
        goto end;
    }
    READ_NEXT(ICMP6_IN_ERR, &ip_statistics.icmp6.in_err);
    READ_NEXT(ICMP6_OUT_MSG, &ip_statistics.icmp6.out_msg);
    READ_NEXT(ICMP6_OUT_ERR, &ip_statistics.icmp6.out_err);

    if (skip_till_prefix(f, line, sizeof(line), "Icmp6InType")) {
        goto end;
    }
    do {
        uint32_t type;
        uint64_t val;
        if (sscanf(line, ICMP6_IN_TYPE, &type, &val) == 2) {
            VALIDATE_ICMP_TYPE(type);
            ip_statistics.icmp6_msg[type].in_pkts = val;
        } else if (sscanf(line, ICMP6_OUT_TYPE, &type, &val) == 2) {
            VALIDATE_ICMP_TYPE(type);
            ip_statistics.icmp6_msg[type].out_pkts = val;
        } else {
            break;
        }
    } while ((line == fgets(line, sizeof(line), f)));

end:
    if (f != NULL) {
        fclose(f);
    }
    return ret;
}

static int skip_till_prefix(FILE *f, char *line, size_t line_len, char *prefix)
{
    int found = 0;
    size_t prefix_len = strlen(prefix);
    do {
        if (!strncmp(prefix, line, prefix_len)) {
            found = 1;
            break;
        }
    } while (line == fgets(line, line_len, f));
    if (!found) {
        return -1;
    }
    return 0;
}
