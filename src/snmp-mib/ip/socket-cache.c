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

#include <dirent.h>
#include <sys/sysinfo.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/rtnetlink.h>
#include <unistd.h>

#include "snmp-core/utils.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-mib/ip/socket-cache.h"

#define UPDATE_INTERVAL 8

typedef struct ProcEntry {
    int inode;
    pid_t pid;
    struct ProcEntry *next;
} ProcEntry;

#define PROC_HASH_SIZE  0x100
static struct ProcEntry **proc_hash;

#define TCP4_STATS_LINE "Tcp: %u %"PRIu32" %"PRIu32" %"PRIi32" %"PRIu64 \
    " %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu32" %"PRIu64" %"PRIu64 \
    " %"PRIu64" %"PRIu64" %"PRIu64" %*u"
#define UDP4_STATS_LINE "Udp: %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64 \
    " %*u %*u %*u %*u"
#define UDP6_IN_DATAGRAMS    "Udp6InDatagrams%*64[ \t]%"PRIu64
#define UDP6_OUT_DATAGRAMS   "Udp6OutDatagrams%*64[ \t]%"PRIu64
#define UDP6_NO_PORTS        "Udp6NoPorts%*64[ \t]%"PRIu64
#define UDP6_IN_ERRS         "Udp6InErrors%*64[ \t]%"PRIu64

static const char *ip4_socket_stat = "/proc/net/snmp";
static const char *ip6_socket_stat = "/proc/net/snmp6";
static const char *sctp_socket_stat = "/proc/net/sctp/snmp";
static const char *sctp_rto_min = "/proc/sys/net/sctp/rto_min";
static const char *sctp_rto_max = "/proc/sys/net/sctp/rto_max";
static const char *sctp_rto_initial = "/proc/sys/net/sctp/rto_initial";
static const char *sctp_val_cookie_lifetime = "/proc/sys/net/sctp/valid_cookie_life";
static const char *sctp_max_init_retr = "/proc/sys/net/sctp/max_init_retransmits";

/* Linux TCP states */
enum {
    LIN_TCP_ESTABLISHED = 1,
    LIN_TCP_SYN_SENT,
    LIN_TCP_SYN_RECV,
    LIN_TCP_FIN_WAIT1,
    LIN_TCP_FIN_WAIT2,
    LIN_TCP_TIME_WAIT,
    LIN_TCP_CLOSE,
    LIN_TCP_CLOSE_WAIT,
    LIN_TCP_LAST_ACK,
    LIN_TCP_LISTEN,
    LIN_TCP_CLOSING,
    LIN_TCP_NEW_SYN_RECV,
    LIN_TCP_MAX_STATES
};

static const enum TCPState const tcp_state_mapping[] = {
    [LIN_TCP_ESTABLISHED] = TCP_STATE_ESTABLISHED,
    [LIN_TCP_SYN_SENT] = TCP_STATE_SYN_SENT,
    [LIN_TCP_NEW_SYN_RECV] = TCP_STATE_SYN_RECEIVED,
    [LIN_TCP_SYN_RECV] = TCP_STATE_SYN_RECEIVED,
    [LIN_TCP_FIN_WAIT1] = TCP_STATE_FIN_WAIT1,
    [LIN_TCP_FIN_WAIT2] = TCP_STATE_FIN_WAIT2,
    [LIN_TCP_TIME_WAIT] = TCP_STATE_TIME_WAIT,
    [LIN_TCP_CLOSE] = TCP_STATE_CLOSED,
    [LIN_TCP_CLOSE_WAIT] = TCP_STATE_CLOSE_WAIT,
    [LIN_TCP_LAST_ACK] = TCP_STATE_LAST_ACK,
    [LIN_TCP_LISTEN] = TCP_STATE_LISTEN,
    [LIN_TCP_CLOSING] = TCP_STATE_CLOSING
};

static void *fetch_socket_stats(void);
static void fetch_socket_list(SocketEntry ***, size_t *,
        size_t *, uint32_t, uint32_t);
static void free_socket_stats(void *);
static int cmp_socket_entries(const void*, const void*);
static int proc_entry_hash(int);
static void proc_hash_destroy(void);
static int proc_hash_build(void);
static pid_t proc_find_entry(int);
static void read_ip4_stats(SocketStats *);
static void read_ip6_stats(SocketStats *);
static void read_sctp_stats(SocketStats *);

SocketStats *get_socket_stats(void)
{
    return get_mib_cache(fetch_socket_stats, free_socket_stats, UPDATE_INTERVAL);
}

static void *fetch_socket_stats(void)
{
    SocketStats *stats = malloc(sizeof(SocketStats));
    if (stats == NULL)
        return NULL;
    memset(stats, 0, sizeof(SocketStats));

    if (proc_hash_build())
        goto err;

    read_ip4_stats(stats);
    read_ip6_stats(stats);
    read_sctp_stats(stats);

    stats->udp_max = 64;
    stats->udp_len = 0;
    stats->udp_arr = malloc(sizeof(SocketEntry *) * stats->udp_max);
    if (stats->udp_arr == NULL)
        goto err;
    fetch_socket_list(&stats->udp_arr, &stats->udp_len, &stats->udp_max, AF_INET, IPPROTO_UDP);
    fetch_socket_list(&stats->udp_arr, &stats->udp_len, &stats->udp_max, AF_INET6, IPPROTO_UDP);

    stats->tcp_max = 64;
    stats->tcp_len = 0;
    stats->tcp_arr = malloc(sizeof(SocketEntry *) * stats->tcp_max);
    if (stats->tcp_arr == NULL)
        goto err;
    fetch_socket_list(&stats->tcp_arr, &stats->tcp_len, &stats->tcp_max, AF_INET, IPPROTO_TCP);
    fetch_socket_list(&stats->tcp_arr, &stats->tcp_len, &stats->tcp_max, AF_INET6, IPPROTO_TCP);

    stats->sctp_max = 64;
    stats->sctp_len = 0;
    stats->sctp_arr = malloc(sizeof(SocketEntry *) * stats->sctp_max);
    if (stats->sctp_arr == NULL)
        goto err;
    fetch_socket_list(&stats->sctp_arr, &stats->sctp_len, &stats->sctp_max, AF_INET, IPPROTO_SCTP);
    fetch_socket_list(&stats->sctp_arr, &stats->sctp_len, &stats->sctp_max, AF_INET6, IPPROTO_SCTP);

    qsort(stats->udp_arr, stats->udp_len, sizeof(SocketEntry *), cmp_socket_entries);
    qsort(stats->tcp_arr, stats->tcp_len, sizeof(SocketEntry *), cmp_socket_entries);
    qsort(stats->sctp_arr, stats->sctp_len, sizeof(SocketEntry *), cmp_socket_entries);

err:
    proc_hash_destroy();
    return stats;
}

static SocketEntry *create_socket_entry(SocketEntry ***arr,
        size_t *arr_len, size_t *arr_max)
{
    SocketEntry *entry = malloc(sizeof(SocketEntry));
    if (entry == NULL)
        return NULL;

    memset(entry, 0, sizeof(SocketEntry));
    if (*arr_len >= *arr_max) {
        int new_len = (*arr_max) << 1;
        SocketEntry **tmp = malloc(new_len * sizeof(SocketEntry *));
        if (tmp == NULL) {
            free(entry);
            return NULL;
        }

        memcpy(*arr, tmp, sizeof(SocketEntry *) * (*arr_max));
        *arr_max = new_len;
        free(*arr);
        *arr = tmp;
    } else {
        (*arr)[(*arr_len)++] = entry;
    }

    return entry;
}

static void fetch_socket_list(SocketEntry ***arr, size_t *arr_len, size_t *arr_max,
        uint32_t family, uint32_t protocol)
{
    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    if (fd == -1)
        goto err;

    struct {
        struct nlmsghdr hdr;
        struct inet_diag_req_v2 msg;
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_req_v2));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.msg.sdiag_protocol = protocol;
    req.msg.sdiag_family = family;
    req.msg.idiag_states = -1;

    if (send(fd, &req, req.hdr.nlmsg_len, 0) < 0)
        goto err;

    int len;
    uint8_t buf[16384];
    struct iovec iov = { buf, sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    int done = 0;
    while (!done) {
        if ((len = recvmsg(fd, &msg, 0)) < 0) {
            goto err;
        } else if (len == 0) {
            break;
        }

        for (struct nlmsghdr *nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, len);
                nh = NLMSG_NEXT(nh,len)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            } else if (nh->nlmsg_type == NLMSG_ERROR) {
                goto err;
            }

            struct inet_diag_msg *diag_msg = NLMSG_DATA(nh);
            if (diag_msg->idiag_family != family)
                continue;

            SocketEntry *entry = create_socket_entry(arr, arr_len, arr_max);
            if (entry == NULL)
                goto err;

            entry->family = diag_msg->idiag_family == AF_INET ?
                    ADDRESS_IP4 : ADDRESS_IP6;
            entry->assoc = 0;
            entry->instance = diag_msg->idiag_inode;
            memcpy(entry->local, diag_msg->id.idiag_src, ADDRESS_LENGTH(entry));
            memcpy(entry->remote, diag_msg->id.idiag_dst, ADDRESS_LENGTH(entry));
            entry->local_port = ntohs(diag_msg->id.idiag_sport);
            entry->remote_port = ntohs(diag_msg->id.idiag_dport);
            entry->pid = proc_find_entry(diag_msg->idiag_inode);
            if (protocol == IPPROTO_TCP) {
                entry->state = diag_msg->idiag_state >= LIN_TCP_MAX_STATES ? 0 :
                    tcp_state_mapping[diag_msg->idiag_state];
            } else if (protocol == IPPROTO_SCTP) {
                /* TODO why is the association ID not included here? */
                entry->assoc = diag_msg->idiag_inode;
                entry->state = diag_msg->idiag_state;
                struct rtattr *local = NULL;
                struct rtattr *peer = NULL;

                uint32_t rta_len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*diag_msg));
                struct rtattr *rta = (struct rtattr *) (diag_msg + 1);
                while (RTA_OK(rta, rta_len)) {
                    if (rta->rta_type == INET_DIAG_LOCALS) {
                        local = rta;
                    } else if (rta->rta_type == INET_DIAG_PEERS) {
                        peer = rta;
                    }
                    rta = RTA_NEXT(rta, rta_len);
                }

                int c = 0;
                if (local != NULL && peer != NULL) {
                    int local_len = RTA_PAYLOAD(local);
                    struct sockaddr_storage *local_sa = RTA_DATA(local);

                    for (; local_len > 0; local_sa++, local_len -= sizeof(*local_sa)) {
                        int peer_len = RTA_PAYLOAD(peer);
                        struct sockaddr_storage *peer_sa = RTA_DATA(peer);

                        for (; peer_len > 0; peer_sa++, peer_len -= sizeof(*peer_sa)) {
                            if (local_sa->ss_family != peer_sa->ss_family)
                                continue;

                            if (c) {
                                SocketEntry *prev_entry = entry;
                                entry = create_socket_entry(arr, arr_len, arr_max);
                                if (entry == NULL)
                                    goto err;
                                memcpy(entry, prev_entry, sizeof(SocketEntry));
                            }

                            entry->family = local_sa->ss_family;
                            if (local_sa->ss_family == AF_INET) {
                                struct sockaddr_in *source = (struct sockaddr_in *) local_sa;
                                struct sockaddr_in *destination = (struct sockaddr_in *) peer_sa;

                                entry->local_port = source->sin_port;
                                entry->remote_port = destination->sin_port;
                                memcpy(entry->local, &source->sin_addr.s_addr, 4);
                                memcpy(entry->remote, &destination->sin_addr.s_addr, 4);
                            } else {
                                struct sockaddr_in6 *source = (struct sockaddr_in6 *) local_sa;
                                struct sockaddr_in6 *destination = (struct sockaddr_in6 *) peer_sa;

                                entry->local_port = source->sin6_port;
                                entry->remote_port = destination->sin6_port;
                                memcpy(entry->local, source->sin6_addr.__in6_u.__u6_addr8, 16);
                                memcpy(entry->remote, destination->sin6_addr.__in6_u.__u6_addr8, 16);
                            }
                            c = 1;
                        }
                    }
                }
            }
        }
    }

err:
    if (fd != -1) {
        close(fd);
    }
}

static void free_socket_stats(void *stats)
{
    SocketStats *s = stats;

    if (s->udp_arr != NULL) {
        for (int i = 0; i < s->udp_len; i++) {
            free(s->udp_arr[i]);
        }
        free(s->udp_arr);
    }

    if (s->tcp_arr != NULL) {
        for (int i = 0; i < s->tcp_len; i++) {
            free(s->tcp_arr[i]);
        }
        free(s->tcp_arr);
    }

    if (s->sctp_arr != NULL) {
        for (int i = 0; i < s->sctp_len; i++) {
            free(s->sctp_arr[i]);
        }
        free(s->sctp_arr);
    }

    free(s);
}

static int cmp_socket_entries(const void *e1, const void *e2)
{
    const SocketEntry *entry1 = *(SocketEntry **) e1;
    const SocketEntry *entry2 = *(SocketEntry **) e2;

    if (entry1->assoc < entry2->assoc) {
        return -1;
    } else if (entry1->assoc > entry2->assoc) {
        return -1;
    }

    if (entry1->family < entry2->family) {
        return -1;
    } else if (entry1->family > entry2->family) {
        return 1;
    }

    int local = memcmp(entry1->local, entry2->local, ADDRESS_LENGTH(entry1));
    if (local != 0) {
        return local;
    }

    if (entry1->local_port < entry2->local_port) {
        return -1;
    } else if (entry1->local_port > entry2->local_port) {
        return 1;
    }

    int remote = memcmp(entry1->remote, entry2->remote, ADDRESS_LENGTH(entry1));
    if (remote != 0) {
        return remote;
    }

    if (entry1->remote_port < entry2->remote_port) {
        return -1;
    } else if (entry1->remote_port > entry2->remote_port) {
        return 1;
    }

    if (entry1->instance < entry2->instance) {
        return -1;
    } else if (entry1->instance > entry2->instance) {
        return 1;
    }

    return 0;
}

static int proc_entry_hash(int inode)
{
    return ((inode >> 24) ^ (inode >> 16) ^ (inode >> 8) ^ inode)
            & (PROC_HASH_SIZE - 1);
}

static void proc_hash_destroy(void)
{
    if (proc_hash != NULL) {
        for (int i = 0; i < PROC_HASH_SIZE; i++) {
            ProcEntry *p = proc_hash[i];
            while (p) {
                ProcEntry *next = p->next;
                free(p);
                p = next;
            }
        }

        free(proc_hash);
        proc_hash = NULL;
    }
}

static int proc_hash_build(void)
{
    proc_hash = malloc(sizeof(ProcEntry *) * PROC_HASH_SIZE);
    if (proc_hash == NULL)
        return -1;
    memset(proc_hash, 0, sizeof(ProcEntry *) * PROC_HASH_SIZE);

    char path[1024];
    path[sizeof(path)-1] = '\0';
    strcpy(path, "/proc/");

    int pathoff = strlen(path);

    DIR *dir = opendir(path);
    if (dir == NULL)
        return -1;

    int ret = 0;
    struct dirent *d;
    while ((d = readdir(dir)) != NULL) {
        int pid;
        if (sscanf(d->d_name, "%d", &pid) != 1)
            continue;

        snprintf(path + pathoff, sizeof(path) - pathoff, "%d/fd/", pid);
        int pos = strlen(path);

        DIR *dir1;
        if ((dir1 = opendir(path)) == NULL)
            continue;

        struct dirent *d1;
        while ((d1 = readdir(dir1)) != NULL) {
            int fd;
            if (sscanf(d1->d_name, "%d", &fd) != 1)
                continue;

            snprintf(path + pos, sizeof(path) - pos, "%d", fd);

            char lnk[64];
            ssize_t link_len = readlink(path, lnk, sizeof(lnk)-1);
            if (link_len == -1)
                continue;
            lnk[link_len] = '\0';

            uint32_t inode;
            if (sscanf(lnk, "socket:[%u]", &inode) != 1)
                continue;

            ProcEntry **pp = &proc_hash[proc_entry_hash(inode)];
            ProcEntry *p = malloc(sizeof(ProcEntry));
            if (p == NULL) {
                ret = -1;
                continue;
            }

            p->inode = inode;
            p->pid = pid;
            p->next = *pp;
            *pp = p;
        }
        closedir(dir1);
    }

    closedir(dir);
    return ret;
}

static pid_t proc_find_entry(int inode)
{
    ProcEntry *p = proc_hash[proc_entry_hash(inode)];

    while (p) {
        if (p->inode == inode)
            return p->pid;
        p = p->next;
    }

    return 0;
}

static void read_ip4_stats(SocketStats *stats)
{
    FILE *f = fopen(ip4_socket_stat, "r");
    if (f == NULL)
        return;

    char line[1024];
    while (line == fgets(line, sizeof(line), f)) {
        if (sscanf(line, TCP4_STATS_LINE,
            &stats->tcp_rto_algo, &stats->tcp_rto_min, &stats->tcp_rto_max,
            &stats->tcp_max_conn, &stats->tcp_active_open, &stats->tcp_passive_open,
            &stats->tcp_attempt_fails, &stats->tcp_estab_reset, &stats->tcp_cur_estab,
            &stats->tcp_in_segs, &stats->tcp_out_segs, &stats->tcp_retrans_segs,
            &stats->tcp_in_errs, &stats->tcp_out_rsts) == 14) {
            break;
        }
    }
    if (stats->tcp_rto_algo == 0) {
        stats->tcp_rto_algo = TCP_RTO_ALGO_OTHER;
    }

    while (line == fgets(line, sizeof(line), f)) {
        if (sscanf(line, UDP4_STATS_LINE,
                &stats->udp_in_dgrams, &stats->udp_in_no_ports,
                &stats->udp_in_errors, &stats->udp_out_dgrams) == 4) {
            break;
        }
    }

    fclose(f);
}

static void read_ip6_stats(SocketStats *stats)
{
    FILE *f = fopen(ip6_socket_stat, "r");
    if (f == NULL)
        return;

    char line[1024];
    int cnt = 0;
    while (cnt < 4 && line == fgets(line, sizeof(line), f)) {
        uint64_t tmp;

        if (strncmp("Udp6", line, 4))
            continue;

        if (sscanf(line, UDP6_IN_DATAGRAMS, &tmp) == 1) {
            stats->udp_in_dgrams += tmp;
            cnt++;
        } else if (sscanf(line, UDP6_NO_PORTS, &tmp) == 1) {
            stats->udp_in_no_ports += tmp;
            cnt++;
        } else if (sscanf(line, UDP6_IN_ERRS, &tmp) == 1) {
            stats->udp_in_errors += tmp;
            cnt++;
        } else if (sscanf(line, UDP6_OUT_DATAGRAMS, &tmp) == 1) {
            stats->udp_out_dgrams += tmp;
            cnt++;
        }
    }

    fclose(f);
}

static void read_sctp_stats(SocketStats *stats)
{
    stats->sctp_rto_algo = SCTP_RTO_ALGO_OTHER;
    stats->sctp_max_assocs = -1;

    FILE *f = fopen(sctp_socket_stat, "r");
    if (f == NULL)
        return;

    char line[1024];
    while (line == fgets(line, sizeof(line), f)) {
        char *delimiter = strchr(line, '\t');
        if (delimiter == NULL)
            continue;
        errno = 0;
        uint64_t val = strtoull(delimiter + 1, NULL, 10);
        if (errno)
            continue;

        if (line[4] == 'C' && line[8] == 'E') {
            stats->sctp_curr_estab = val;
        } else if (line[4] == 'A' && line[10] == 'E') {
            stats->sctp_active_estabs = val;
        } else if (line[4] == 'P' && line[11] == 'E') {
            stats->sctp_passive_estabs = val;
        } else if (line[4] == 'A' && line[5] == 'b') {
            stats->sctp_aborteds = val;
        } else if (line[4] == 'S' && line[5] == 'h') {
            stats->sctp_shutdowns = val;
        } else if (line[4] == 'O' && line[9] == 'B') {
            stats->sctp_out_of_blues = val;
        } else if (line[6] == 'e') {
            stats->sctp_checksum_errors = val;
        } else if (line[4] == 'O') {
            if (line[7] == 'C') {
                stats->sctp_out_ctrl_chunks = val;
            } else if (line[7] == 'O') {
                stats->sctp_out_order_chunks = val;
            } else if (line[7] == 'U') {
                stats->sctp_out_unorder_chunks = val;
            } else if (line[7] == 'S') {
                stats->sctp_out_sctp_packs = val;
            }
        } else if (line[4] == 'I') {
            if (line[6] == 'C') {
                stats->sctp_in_ctrl_chunks = val;
            } else if (line[6] == 'O') {
                stats->sctp_in_order_chunks = val;
            } else if (line[6] == 'U') {
                stats->sctp_in_unorder_chunks = val;
            } else if (line[6] == 'S') {
                stats->sctp_in_sctp_packs = val;
            }
        } else if (line[4] == 'F' && line[8] == 'U') {
            stats->sctp_frag_usr_msgs = val;
        } else if (line[4] == 'R') {
            stats->sctp_reasm_usr_msgs = val;
        }
    }

    fclose(f);

    read_unsigned_from_file(sctp_rto_min, &stats->sctp_rto_min);
    read_unsigned_from_file(sctp_rto_max, &stats->sctp_rto_max);
    read_unsigned_from_file(sctp_rto_initial, &stats->sctp_rto_initial);
    read_unsigned_from_file(sctp_val_cookie_lifetime, &stats->sctp_val_cookie_life);
    read_unsigned_from_file(sctp_max_init_retr, &stats->sctp_max_init_retr);
}
