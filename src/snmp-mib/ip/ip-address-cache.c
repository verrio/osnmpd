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
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/ip/ip-address-cache.h"

#define UPDATE_INTERVAL 8

static const uint8_t link_local_prefix[] = {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static void *fetch_ip_addresses(void);
static void free_ip_addresses(void *);
static void *fetch_ip_to_phy_mapping(void);
static void free_ip_to_phy_mapping(void *);
static void *fetch_ip_default_routes(void);
static void free_ip_default_routes(void *);
static int cmp_ip_entries(const void *, const void *);
static void *next_ip_entry(void *);
static void set_next_ip_entry(void *, void *);
static int cmp_ndp_entries(const void *, const void *);
static void *next_ndp_entry(void *);
static void set_next_ndp_entry(void *, void *);
static int cmp_default_route_entries(const void *, const void *);
static void *next_default_route_entry(void *);
static void set_next_default_route_entry(void *, void *);

IpAddressEntry *get_ip_address_list(void)
{
    return get_mib_cache(fetch_ip_addresses, free_ip_addresses, UPDATE_INTERVAL);
}

IpToPhysicalAddressEntry *get_ip_to_phy_address_list(void)
{
    return get_mib_cache(fetch_ip_to_phy_mapping,
            free_ip_to_phy_mapping, UPDATE_INTERVAL);
}

IpDefaultRouteEntry *get_ip_default_route_list(void)
{
    return get_mib_cache(fetch_ip_default_routes,
            free_ip_default_routes, UPDATE_INTERVAL);
}

static void *fetch_ip_addresses(void)
{
    IpAddressEntry *head = NULL;
    IpAddressEntry *cur = NULL;

    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd == -1)
        goto err;

    struct {
        struct nlmsghdr hdr;
        struct rtgenmsg msg;
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(req.msg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = RTM_GETADDR;
    req.msg.rtgen_family = AF_UNSPEC;

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
            } else if (nh->nlmsg_type == NLMSG_ERROR) {
                goto err;
            }

            struct ifaddrmsg *addr = NLMSG_DATA(nh);
            if (addr->ifa_family != AF_INET && addr->ifa_family != AF_INET6)
                continue;

            IpAddressEntry *new = malloc(sizeof(IpAddressEntry));
            if (new == NULL)
                goto err;

            memset(new, 0, sizeof(IpAddressEntry));
            if (cur == NULL)
                head = new;
            else
                cur->next = new;

            cur = new;
            cur->family = addr->ifa_family == AF_INET ? ADDRESS_IP4 : ADDRESS_IP6;
            cur->iface = addr->ifa_index;
            cur->prefix = addr->ifa_prefixlen;
            cur->address_type = IP_ADDRESSING_TYPE_UNICAST;
            if (addr->ifa_family == AF_INET
                || (addr->ifa_flags & IFA_F_TEMPORARY)
                || (addr->ifa_flags & IFA_F_PERMANENT))
                cur->status = IP_ADDRESS_STATUS_PREFERRED;
            else if (addr->ifa_flags & IFA_F_DEPRECATED)
                cur->status = IP_ADDRESS_STATUS_DEPRECATED;
            else if (addr->ifa_flags & IFA_F_TENTATIVE)
                cur->status = IP_ADDRESS_STATUS_TENTATIVE;
            else
                cur->status = IP_ADDRESS_STATUS_UNKNOWN;

            /* attributes */
            unsigned int attr_len = IFA_PAYLOAD(nh);
            for (struct rtattr *attr = IFA_RTA(addr); RTA_OK(attr, attr_len) == 1;
                    attr = RTA_NEXT(attr, attr_len)) {
                switch (attr->rta_type) {
                    case IFA_ADDRESS: {
                        memcpy(cur->address, RTA_DATA(attr), min(16, RTA_PAYLOAD(attr)));
                        break;
                    }

                    case IFA_ANYCAST: {
                        cur->address_type = IP_ADDRESSING_TYPE_ANYCAST;
                        memcpy(cur->address, RTA_DATA(attr), min(16, RTA_PAYLOAD(attr)));
                        break;
                    }

                    case IFA_CACHEINFO: {
                        if (RTA_PAYLOAD(attr) < sizeof(struct ifa_cacheinfo)) {
                            goto err;
                        }
                        struct ifa_cacheinfo *info = RTA_DATA(attr);
                        cur->created = info->cstamp;
                        cur->last_changed = info->tstamp;
                        cur->valid = info->ifa_valid;
                        cur->preferred = info->ifa_prefered;
                        break;
                    }
                }
            }

            if (!addr->ifa_flags || (addr->ifa_family == AF_INET6
                    && !memcmp(cur->address, link_local_prefix, 8)))
                cur->origin = IP_ADDRESS_ORIGIN_LINKLAYER;
            else if (addr->ifa_flags & IFA_F_TEMPORARY)
                cur->origin = IP_ADDRESS_ORIGIN_RANDOM;
            else
                cur->origin = IP_ADDRESS_ORIGIN_MANUAL;
        }
    }

err:
    if (fd != -1)
        close(fd);
    return sort_list(head, cmp_ip_entries, next_ip_entry, set_next_ip_entry);
}

static void free_ip_addresses(void *head)
{
    IpAddressEntry *next = head;

    while (next != NULL) {
        IpAddressEntry *cur = next;
        next = next->next;
        free(cur);
    }
}

static void *fetch_ip_to_phy_mapping(void)
{
    IpToPhysicalAddressEntry *head = NULL;
    IpToPhysicalAddressEntry *cur = NULL;

    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd == -1)
        goto err;

    struct {
        struct nlmsghdr hdr;
        struct ndmsg msg;
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = RTM_GETNEIGH;
    req.msg.ndm_state = (0xff & ~NUD_NOARP);

    if (send(fd, &req, req.hdr.nlmsg_len, 0) < 0)
        goto err;

    int len;
    uint8_t buf[16384];
    struct iovec iov = { buf, sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    long int hz = sysconf(_SC_CLK_TCK);
    if (hz == -1)
        goto err;

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
            } else if (nh->nlmsg_type == NLMSG_ERROR) {
                goto err;
            }

            struct ndmsg *ndp = NLMSG_DATA(nh);
            if (ndp->ndm_family != AF_INET && ndp->ndm_family != AF_INET6)
                continue;

            IpToPhysicalAddressEntry *new = malloc(sizeof(IpToPhysicalAddressEntry));
            if (new == NULL)
                goto err;

            memset(new, 0, sizeof(IpToPhysicalAddressEntry));
            if (cur == NULL)
                head = new;
            else
                cur->next = new;

            cur = new;
            cur->family = ndp->ndm_family == AF_INET ? ADDRESS_IP4 : ADDRESS_IP6;
            cur->iface = ndp->ndm_ifindex;

            if (ndp->ndm_state & NUD_PERMANENT)
                cur->mapping = IP_TO_PHY_TYPE_STATIC;
            else if (ndp->ndm_state & NUD_FAILED)
                cur->mapping = IP_TO_PHY_TYPE_INVALID;
            else if (ndp->ndm_state & NUD_NOARP)
                cur->mapping = IP_TO_PHY_TYPE_OTHER;
            else
                cur->mapping = IP_TO_PHY_TYPE_DYNAMIC;

            if (ndp->ndm_state & NUD_INCOMPLETE)
                cur->state = IP_TO_PHY_STATE_INCOMPLETE;
            else if (ndp->ndm_state & NUD_REACHABLE)
                cur->state = IP_TO_PHY_STATE_REACHABLE;
            else if (ndp->ndm_state & NUD_STALE)
                cur->state = IP_TO_PHY_STATE_STALE;
            else if (ndp->ndm_state & NUD_DELAY)
                cur->state = IP_TO_PHY_STATE_DELAY;
            else if (ndp->ndm_state & NUD_PROBE)
                cur->state = IP_TO_PHY_STATE_PROBE;
            else if (ndp->ndm_state & NUD_FAILED)
                cur->state = IP_TO_PHY_STATE_INVALID;
            else
                cur->state = IP_TO_PHY_STATE_UNKNOWN;

            /* attributes */
            unsigned int ndl = RTM_PAYLOAD(nh);

            for (struct rtattr *ndap = RTM_RTA(ndp); RTA_OK(ndap, ndl) == 1;
                ndap = RTA_NEXT(ndap, ndl)) {
                switch (ndap->rta_type) {
                    case NDA_DST: {
                        memcpy(cur->address, RTA_DATA(ndap), min(16, RTA_PAYLOAD(ndap)));
                        break;
                    }

                    case NDA_LLADDR: {
                        cur->physical_len = min(64, RTA_PAYLOAD(ndap));
                        memcpy(cur->physical, RTA_DATA(ndap), cur->physical_len);
                        break;
                    }

                    case NDA_CACHEINFO: {
                        struct nda_cacheinfo *ci = RTA_DATA(ndap);
                        cur->last_changed = rebase_duration(ci->ndm_updated / hz);
                        break;
                    }
                }
            }
        }
    }

err:
    if (fd != -1)
        close(fd);
    return sort_list(head, cmp_ndp_entries, next_ndp_entry, set_next_ndp_entry);
}

static void free_ip_to_phy_mapping(void *head)
{
    IpToPhysicalAddressEntry *next = head;

    while (next != NULL) {
        IpToPhysicalAddressEntry *cur = next;
        next = next->next;
        free(cur);
    }
}

static void *fetch_ip_default_routes(void)
{
    IpDefaultRouteEntry *head = NULL;
    IpDefaultRouteEntry *cur = NULL;

    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd == -1)
        goto err;

    struct {
        struct nlmsghdr hdr;
        struct rtmsg msg;
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = RTM_GETROUTE;
    /* include all routing tables */

    if (send(fd, &req, req.hdr.nlmsg_len, 0) < 0)
        goto err;

    int len;
    uint8_t buf[16384];
    struct iovec iov = { buf, sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    long int hz = sysconf(_SC_CLK_TCK);
    if (hz == -1)
        goto err;

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
            } else if (nh->nlmsg_type == NLMSG_ERROR) {
                goto err;
            }

            struct rtmsg *rtmp = NLMSG_DATA(nh);
            if (rtmp->rtm_dst_len != 0 || rtmp->rtm_type != RTN_UNICAST ||
                (rtmp->rtm_family != AF_INET && rtmp->rtm_family != AF_INET6))
                continue;
            IpDefaultRouteEntry *new = malloc(sizeof(IpDefaultRouteEntry));
            if (new == NULL)
                goto err;

            memset(new, 0, sizeof(IpDefaultRouteEntry));
            if (cur == NULL)
                head = new;
            else
                cur->next = new;

            cur = new;
            cur->family = rtmp->rtm_family == AF_INET ? ADDRESS_IP4 : ADDRESS_IP6;
            cur->lifetime = UINT32_MAX;
            cur->preference = 0;

            /* attributes */
            unsigned int rtap_len = RTM_PAYLOAD(nh);
            for (struct rtattr *rtap = RTM_RTA(rtmp); RTA_OK(rtap, rtap_len) == 1;
                rtap = RTA_NEXT(rtap, rtap_len)){
                switch (rtap->rta_type) {
                    case RTA_OIF: {
                        cur->iface = *(int *)(RTA_DATA(rtap));
                        break;
                    }

                    case RTA_GATEWAY: {
                        memcpy(cur->address, RTA_DATA(rtap), min(RTA_PAYLOAD(rtap), 16));
                        break;
                    }

                    case RTA_CACHEINFO: {
                        if (RTA_PAYLOAD(rtap) < sizeof(struct rta_cacheinfo)) {
                            continue;
                        }
                        cur->lifetime = ((struct rta_cacheinfo *)
                                RTA_DATA(rtap))->rta_expires / hz;
                        break;
                    }
                }
            }
        }
    }

err:
    if (fd != -1)
        close(fd);
    return sort_list(head, cmp_default_route_entries,
        next_default_route_entry, set_next_default_route_entry);
}

static void free_ip_default_routes(void *head)
{
    IpDefaultRouteEntry *next = head;

    while (next != NULL) {
        IpDefaultRouteEntry *cur = next;
        next = next->next;
        free(cur);
    }
}

static int cmp_ip_entries(const void *entry1, const void *entry2)
{
    if (((IpAddressEntry *) entry1)->family <
        ((IpAddressEntry *) entry2)->family)
        return -1;
    else if (((IpAddressEntry *) entry1)->family >
        ((IpAddressEntry *) entry2)->family)
        return 1;

    int len = ADDRESS_LENGTH(entry1);
    for (int i = 0; i < len; i++) {
        if (((IpAddressEntry *) entry1)->address[i] <
                ((IpAddressEntry *) entry2)->address[i])
            return -1;
        else if (((IpAddressEntry *) entry1)->address[i] >
                ((IpAddressEntry *) entry2)->address[i])
            return 1;
    }

    return 0;
}

static void *next_ip_entry(void *entry)
{
    return ((IpAddressEntry *) entry)->next;
}

static void set_next_ip_entry(void *entry, void *next)
{
    ((IpAddressEntry *) entry)->next = next;
}

static int cmp_ndp_entries(const void *entry1, const void *entry2)
{
    if (((IpToPhysicalAddressEntry *) entry1)->iface <
        ((IpToPhysicalAddressEntry *) entry2)->iface)
        return -1;
    else if (((IpToPhysicalAddressEntry *) entry1)->iface >
        ((IpToPhysicalAddressEntry *) entry2)->iface)
        return 1;

    if (((IpToPhysicalAddressEntry *) entry1)->family <
        ((IpToPhysicalAddressEntry *) entry2)->family)
        return -1;
    else if (((IpToPhysicalAddressEntry *) entry1)->family >
        ((IpToPhysicalAddressEntry *) entry2)->family)
        return 1;

    int len = ADDRESS_LENGTH(entry1);
    for (int i = 0; i < len; i++) {
        if (((IpToPhysicalAddressEntry *) entry1)->address[i] <
                ((IpToPhysicalAddressEntry *) entry2)->address[i])
            return -1;
        else if (((IpToPhysicalAddressEntry *) entry1)->address[i] >
                ((IpToPhysicalAddressEntry *) entry2)->address[i])
            return 1;
    }

    return 0;
}

static void *next_ndp_entry(void *entry)
{
    return ((IpToPhysicalAddressEntry *) entry)->next;
}

static void set_next_ndp_entry(void *entry, void *next)
{
    ((IpToPhysicalAddressEntry *) entry)->next = next;
}

static int cmp_default_route_entries(const void *entry1, const void *entry2)
{
    if (((IpDefaultRouteEntry *) entry1)->family <
        ((IpDefaultRouteEntry *) entry2)->family)
        return -1;
    else if (((IpDefaultRouteEntry *) entry1)->family >
        ((IpDefaultRouteEntry *) entry2)->family)
        return 1;

    int len = ADDRESS_LENGTH(entry1);
    for (int i = 0; i < len; i++) {
        if (((IpDefaultRouteEntry *) entry1)->address[i] <
                ((IpDefaultRouteEntry *) entry2)->address[i])
            return -1;
        else if (((IpDefaultRouteEntry *) entry1)->address[i] >
                ((IpDefaultRouteEntry *) entry2)->address[i])
            return 1;
    }

    if (((IpDefaultRouteEntry *) entry1)->iface <
        ((IpDefaultRouteEntry *) entry2)->iface)
        return -1;
    else if (((IpDefaultRouteEntry *) entry1)->iface >
        ((IpDefaultRouteEntry *) entry2)->iface)
        return 1;

    return 0;
}

static void *next_default_route_entry(void *entry)
{
    return ((IpDefaultRouteEntry *) entry)->next;
}

static void set_next_default_route_entry(void *entry, void *next)
{
    ((IpDefaultRouteEntry *) entry)->next = next;
}
