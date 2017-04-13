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

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ipv6.h>
#include <linux/snmp.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/ip/if-cache.h"

#define UPDATE_INTERVAL 8

static char *retrans_file = "/proc/sys/net/ipv4/neigh/%s/retrans_time_ms";

static void *fetch_if_stats(void);
static void free_if_stats(void *head);
static int cmp_if_entries(const void *, const void *);
static void *next_if_entry(void *);
static void set_next_if_entry(void *, void *);
static enum IfType translate_if_type(int);
static enum IfOperState translate_if_oper_state(int);
static void fetch_if_ethtool_stats(IfaceEntry *);

IfaceEntry *get_iface_list(void)
{
    return get_mib_cache(fetch_if_stats, free_if_stats, UPDATE_INTERVAL);
}

static void *fetch_if_stats(void)
{
    IfaceEntry *head = NULL;
    IfaceEntry *cur = NULL;

    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd == -1)
        goto err;

    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg msg;
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.msg.ifi_family = AF_UNSPEC;

    if (send(fd, &req, req.hdr.nlmsg_len, 0) < 0)
        goto err;

    int len;
    uint8_t buf[16384];
    struct iovec iov = { buf, sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    int done = 0;
    while (!done) {
        if ((len = recvmsg(fd, &msg, 0)) < 0)
            goto err;
        if (len == 0)
            break;

        for (struct nlmsghdr *nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, len);
                nh = NLMSG_NEXT(nh,len)) {
            /* header */
            if (nh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            } else if (nh->nlmsg_type != RTM_NEWLINK) {
                goto err;
            }

            struct ifinfomsg *ifinfo = (struct ifinfomsg *) NLMSG_DATA(nh);

            IfaceEntry *new = malloc(sizeof(IfaceEntry));
            if (new == NULL)
                goto err;

            memset(new, 0, sizeof(IfaceEntry));
            if (cur == NULL)
                head = new;
            else
                cur->next = new;

            cur = new;
            cur->id = ifinfo->ifi_index;
            cur->type = translate_if_type(ifinfo->ifi_type);
            cur->mac_stats.admin_state = (ifinfo->ifi_flags & IFF_UP) ? 1 : 2;
            cur->mac_stats.promiscuous_state = 2;
            /* TODO: IPv4 state follows the iface admin state? */
            cur->ip4_stats.admin_state = cur->mac_stats.admin_state;
            cur->ip6_stats.admin_state = 2;
            cur->ip6_stats.forwarding = 2;

            /* attributes */
            unsigned int ndl = NLMSG_PAYLOAD(nh, sizeof(struct ifinfomsg));
            for (struct rtattr *attr = (struct rtattr *) IFLA_RTA(ifinfo);
                    RTA_OK(attr, ndl) == 1; attr = RTA_NEXT(attr, ndl)) {
                switch (attr->rta_type) {
                    case IFLA_IFNAME: {
                        strncpy(cur->iface_name, RTA_DATA(attr),
                                min(RTA_PAYLOAD(attr), IFNAMSIZ-1));
                        cur->iface_name[IFNAMSIZ-1] = '\0';

                        /* retransmission time for IPv4 */
                        char buf[64];
                        sprintf(buf, retrans_file, cur->iface_name);
                        read_unsigned_from_file(buf, &cur->ip4_stats.retrans_time);
                        break;
                    }

                    case IFLA_ADDRESS: {
                        cur->address_len = min(RTA_PAYLOAD(attr), 64);
                        memcpy(cur->address, RTA_DATA(attr), cur->address_len);
                        break;
                    }

                    case IFLA_AF_SPEC: {
                        unsigned int nlen = RTA_PAYLOAD(attr);
                        for (struct rtattr *nattr = RTA_DATA(attr);
                             RTA_OK(nattr, nlen) == 1;
                             nattr = RTA_NEXT(nattr, nlen)) {
                            if (nattr->rta_type != AF_INET6) {
                                continue;
                            }

                            unsigned int nlen2 = RTA_PAYLOAD(nattr);
                            for (struct rtattr *nattr2 = RTA_DATA(nattr);
                                RTA_OK(nattr2, nlen2) == 1;
                                nattr2 = RTA_NEXT(nattr2, nlen2)) {
                                switch (nattr2->rta_type) {
                                    case IFLA_INET6_CACHEINFO: {
                                        struct ifla_cacheinfo *val = RTA_DATA(nattr2);
                                        cur->ip6_stats.max_reasm_len = val->max_reasm_len;
                                        cur->ip6_stats.reachable_time = val->reachable_time;
                                        cur->ip6_stats.retrans_time = val->retrans_time;
                                        cur->ip6_stats.updated = val->tstamp;
                                        break;
                                    }

                                    case IFLA_INET6_STATS: {
                                        uint64_t *stats = RTA_DATA(nattr2);
                                        if (RTA_PAYLOAD(nattr2) /
                                                sizeof(uint64_t) < __IPSTATS_MIB_MAX) {
                                            break;
                                        }

                                        cur->ip6_stats.in_receives =
                                                stats[IPSTATS_MIB_INPKTS];
                                        cur->ip6_stats.in_octets =
                                                stats[IPSTATS_MIB_INOCTETS];
                                        cur->ip6_stats.in_hdr_errors =
                                                stats[IPSTATS_MIB_INHDRERRORS];
                                        cur->ip6_stats.in_no_routes =
                                                stats[IPSTATS_MIB_INNOROUTES];
                                        cur->ip6_stats.in_addr_errors =
                                                stats[IPSTATS_MIB_INADDRERRORS];
                                        cur->ip6_stats.in_unknown_protos =
                                                stats[IPSTATS_MIB_INUNKNOWNPROTOS];
                                        cur->ip6_stats.in_truncated_pkts =
                                                stats[IPSTATS_MIB_INTRUNCATEDPKTS];
                                        cur->ip6_stats.reasm_ok =
                                                stats[IPSTATS_MIB_REASMOKS];
                                        cur->ip6_stats.reasm_fails =
                                                stats[IPSTATS_MIB_REASMFAILS];
                                        cur->ip6_stats.reasm_reqds =
                                                stats[IPSTATS_MIB_REASMREQDS];
                                        cur->ip6_stats.in_discards =
                                                stats[IPSTATS_MIB_INDISCARDS];
                                        cur->ip6_stats.in_delivers =
                                                stats[IPSTATS_MIB_INDELIVERS];
                                        cur->ip6_stats.out_requests =
                                                stats[IPSTATS_MIB_OUTPKTS];
                                        cur->ip6_stats.out_forw_datagrams =
                                                stats[IPSTATS_MIB_OUTFORWDATAGRAMS];
                                        cur->ip6_stats.out_discards =
                                                stats[IPSTATS_MIB_OUTDISCARDS];
                                        cur->ip6_stats.out_frag_oks =
                                                stats[IPSTATS_MIB_FRAGOKS];
                                        cur->ip6_stats.out_frag_fails =
                                                stats[IPSTATS_MIB_FRAGFAILS];
                                        cur->ip6_stats.out_frag_creates =
                                                stats[IPSTATS_MIB_FRAGCREATES];
                                        cur->ip6_stats.out_octets =
                                                stats[IPSTATS_MIB_OUTOCTETS];
                                        cur->ip6_stats.in_mcast_pkts =
                                                stats[IPSTATS_MIB_INMCASTPKTS];
                                        cur->ip6_stats.in_mcast_octets =
                                                stats[IPSTATS_MIB_INMCASTOCTETS];
                                        cur->ip6_stats.out_mcast_pkts =
                                                stats[IPSTATS_MIB_OUTMCASTPKTS];
                                        cur->ip6_stats.out_mcast_octets =
                                                stats[IPSTATS_MIB_OUTMCASTOCTETS];
                                        break;
                                    }

                                    case IFLA_INET6_CONF: {
                                        uint32_t *devconf = (uint32_t *) RTA_DATA(nattr2);
                                        size_t len = RTA_PAYLOAD(nattr2) / sizeof(uint32_t);

                                        if (DEVCONF_FORWARDING < len) {
                                            cur->ip6_stats.forwarding =
                                                devconf[DEVCONF_FORWARDING] ? 1 : 2;
                                        }
                                        if (DEVCONF_DISABLE_IPV6 < len) {
                                            cur->ip6_stats.admin_state =
                                                ((ifinfo->ifi_flags & IFF_UP) &&
                                                    !devconf[DEVCONF_DISABLE_IPV6]) ? 1 : 2;
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        break;
                    }

                    case IFLA_LINK: {
                        cur->iface_link = *(uint32_t *) RTA_DATA(attr);
                        break;
                    }

                    case IFLA_TXQLEN: {
                        cur->mac_stats.tx_qlen = *(uint32_t *) RTA_DATA(attr);
                        break;
                    }

                    case IFLA_OPERSTATE: {
                        cur->mac_stats.oper_state =
                            translate_if_oper_state(*(uint8_t *) RTA_DATA(attr));
                        break;
                    }

                    case IFLA_MTU: {
                        cur->mac_stats.mtu = *(uint32_t *) RTA_DATA(attr);
                        break;
                    }

                    case IFLA_PROMISCUITY: {
                        cur->mac_stats.promiscuous_state =
                            (*(uint32_t *) RTA_DATA(attr)) > 0 ? 1 : 2;
                        break;
                    }

                    case IFLA_STATS64: {
                        struct rtnl_link_stats64 *stats = RTA_DATA(attr);
                        if (RTA_PAYLOAD(attr) < sizeof(struct rtnl_link_stats64)) {
                            break;
                        }

                        cur->mac_stats.out_errs = stats->tx_errors;
                        cur->mac_stats.out_discards = stats->tx_dropped;
                        cur->mac_stats.out_ucast_pkts = stats->tx_packets;
                        cur->mac_stats.out_octets = stats->tx_bytes;
                        cur->mac_stats.in_unknown_proto = stats->rx_nohandler;
                        cur->mac_stats.in_errs = stats->rx_errors;
                        cur->mac_stats.in_discards = stats->rx_dropped;
                        cur->mac_stats.in_ucast_pkts = stats->rx_packets;
                        cur->mac_stats.in_mcast_pkts = stats->multicast;
                        cur->mac_stats.in_octets = stats->rx_bytes;
                        break;
                    }
                }
            }

            fetch_if_ethtool_stats(cur);
            cur->mac_stats.out_ucast_pkts -= cur->mac_stats.out_mcast_pkts;
            cur->mac_stats.out_ucast_pkts -= cur->mac_stats.out_bcast_pkts;
            cur->mac_stats.in_ucast_pkts -= cur->mac_stats.in_mcast_pkts;
            cur->mac_stats.in_ucast_pkts -= cur->mac_stats.in_bcast_pkts;
        }
    }

err:
    if (fd != -1)
        close(fd);

    return sort_list(head, cmp_if_entries, next_if_entry, set_next_if_entry);
}

static void fetch_if_ethtool_stats(IfaceEntry *entry)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return;

    struct ethtool_gstrings *strings = NULL;
    struct ethtool_stats *stats = NULL;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, entry->iface_name, strlen(entry->iface_name));

    /* driver info */
    struct ethtool_drvinfo drvinfo;
    memset(&drvinfo, 0, sizeof(drvinfo));
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    ifr.ifr_data = (void *) &drvinfo;

    if (ioctl(s, SIOCETHTOOL, &ifr) == -1)
        goto err;

    snprintf(entry->iface_descr, MAX_IF_DESCR, "Driver: %s %s - Bus: %s - FW: %s",
        drvinfo.driver, drvinfo.version, drvinfo.bus_info, drvinfo.fw_version);

    /* statistics */
    if (drvinfo.n_stats > 0) {
        strings = calloc(1, sizeof(struct ethtool_gstrings)
                    + drvinfo.n_stats * ETH_GSTRING_LEN);
        if (strings == NULL)
            goto err;
        strings->cmd = ETHTOOL_GSTRINGS;
        strings->string_set = ETH_SS_STATS;
        strings->len = drvinfo.n_stats;

        ifr.ifr_data = (void *) strings;
        if (ioctl(s, SIOCETHTOOL, &ifr) == -1)
            goto err;

        stats = calloc(1, sizeof(struct ethtool_stats)
                + drvinfo.n_stats * sizeof(uint64_t));
        if (stats == NULL)
            goto err;
        stats->cmd = ETHTOOL_GSTATS;
        stats->n_stats = drvinfo.n_stats;
        ifr.ifr_data = (void *) stats;

        if (ioctl(s, SIOCETHTOOL, &ifr) == -1)
            goto err;

        int found = 0;
        for (int i = 0; found < 4 && i < drvinfo.n_stats; i++) {
            if (!strncmp((char *) strings->data +
                    i * ETH_GSTRING_LEN, "tx_broadcast", ETH_GSTRING_LEN)) {
                entry->mac_stats.out_bcast_pkts = stats->data[i];
                found++;
            } else if (!strncmp((char *) strings->data +
                    i * ETH_GSTRING_LEN, "rx_broadcast", ETH_GSTRING_LEN)) {
                entry->mac_stats.in_bcast_pkts = stats->data[i];
                found++;
            } else if (!strncmp((char *) strings->data +
                    i * ETH_GSTRING_LEN, "tx_multicast", ETH_GSTRING_LEN)) {
                entry->mac_stats.out_mcast_pkts = stats->data[i];
                found++;
            } else if (!strncmp((char *) strings->data +
                    i * ETH_GSTRING_LEN, "rx_multicast", ETH_GSTRING_LEN)) {
                entry->mac_stats.in_mcast_pkts = stats->data[i];
                found++;
            }
        }
    }

    /* speed */
    struct ethtool_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (void *) &cmd;

    if (ioctl(s, SIOCETHTOOL, &ifr) != -1)
        entry->mac_stats.speed = 1000000 * (uint64_t) ethtool_cmd_speed(&cmd);

err:
    free(stats);
    free(strings);
    close(s);
}

static void free_if_stats(void *head)
{
    IfaceEntry *next = head;

    while (next != NULL) {
        IfaceEntry *cur = next;
        next = next->next;
        free(cur);
    }
}

static int cmp_if_entries(const void *entry1, const void *entry2)
{
    if (((IfaceEntry *) entry1)->id < ((IfaceEntry *) entry2)->id)
        return -1;
    else if (((IfaceEntry *) entry1)->id > ((IfaceEntry *) entry2)->id)
        return 1;

    return 0;
}

static void *next_if_entry(void *entry)
{
    return ((IfaceEntry *) entry)->next;
}

static void set_next_if_entry(void *entry, void *next)
{
    ((IfaceEntry *) entry)->next = next;
}

static enum IfType translate_if_type(int type)
{
    switch (type) {
        case ARPHRD_LOOPBACK: {
            return IF_TYPE_SOFTWARE_LOOP_BACK;
        }

        case ARPHRD_ETHER:
        case ARPHRD_EETHER:
        case ARPHRD_IEEE802: {
            return IF_TYPE_ETHERNET_CSMA_CD;
        }

        case ARPHRD_IEEE80211:
        case ARPHRD_IEEE80211_PRISM:
        case ARPHRD_IEEE80211_RADIOTAP: {
            return IF_TYPE_IEEE_802_11;
        }

        case ARPHRD_TUNNEL:
        case ARPHRD_TUNNEL6:
        case ARPHRD_SIT:
        case ARPHRD_IPGRE:
        case ARPHRD_IP6GRE: {
            return IF_TYPE_TUNNEL;
        }

        case ARPHRD_AX25: {
            return IF_TYPE_RADIO_MAC;
        }

        case ARPHRD_SLIP:
        case ARPHRD_CSLIP:
        case ARPHRD_SLIP6:
        case ARPHRD_CSLIP6: {
            return IF_TYPE_SLIP;
        }

        case ARPHRD_PPP: {
            return IF_TYPE_PPP;
        }

        case ARPHRD_HDLC: {
            return IF_TYPE_HDLC;
        }

        case ARPHRD_FCPP:
        case ARPHRD_FCAL:
        case ARPHRD_FCPL:
        case ARPHRD_FCFABRIC: {
            return IF_TYPE_FIBRE_CHANNEL;
        }

        case ARPHRD_IEEE802154:
        case ARPHRD_IEEE802154_MONITOR:
        case ARPHRD_6LOWPAN: {
            return IF_TYPE_IEEE_802_1_54;
        }

        default: {
            return IF_TYPE_OTHER;
        }
    }
}

static enum IfOperState translate_if_oper_state(int state)
{
    switch (state) {
        case IF_OPER_NOTPRESENT: {
            return IF_OPER_NOTPRESENT;
        }

        case IF_OPER_DOWN: {
            return IF_OPER_DOWN;
        }

        case IF_OPER_LOWERLAYERDOWN: {
            return IF_OPER_LOWERLAYERDOWN;
        }

        case IF_OPER_TESTING: {
            return IF_OPER_TESTING;
        }

        case IF_OPER_DORMANT: {
            return IF_OPER_DORMANT;
        }

        case IF_OPER_UP: {
            return IF_OPER_UP;
        }

        default: {
            return IF_OPER_UNKNOWN;
        }
    }
}
