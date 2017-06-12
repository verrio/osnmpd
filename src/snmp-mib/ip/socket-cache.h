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

#ifndef SRC_SNMP_MIB_IP_SOCKET_CACHE_H_
#define SRC_SNMP_MIB_IP_SOCKET_CACHE_H_

#include <sys/types.h>
#include "snmp-mib/ip/ip-address-cache.h"

enum TransportType {
    TRANSPORT_UDP,
    TRANSPORT_TCP,
    TRANSPORT_SCTP
};

enum TCPRtoAlgorithm {
    TCP_RTO_ALGO_OTHER = 1,
    TCP_RTO_ALGO_CONSTANT = 2,
    TCP_RTO_ALGO_RSRE = 3,
    TCP_RTO_ALGO_VANJ = 4,
    TCP_RTO_ALGO_RFC2988 = 5,
};

enum SCTPRtoAlgorithm {
    SCTP_RTO_ALGO_OTHER = 1,
    SCTP_RTO_ALGO_VANJ = 2
};

enum TCPState {
    TCP_STATE_CLOSED = 1,
    TCP_STATE_LISTEN = 2,
    TCP_STATE_SYN_SENT = 3,
    TCP_STATE_SYN_RECEIVED = 4,
    TCP_STATE_ESTABLISHED = 5,
    TCP_STATE_FIN_WAIT1 = 6,
    TCP_STATE_FIN_WAIT2 = 7,
    TCP_STATE_CLOSE_WAIT = 8,
    TCP_STATE_LAST_ACK = 9,
    TCP_STATE_CLOSING = 10,
    TCP_STATE_TIME_WAIT = 11,
    TCP_STATE_DELETE_TCB = 12
};

typedef struct {
    enum IpAddressFamily family;
    uint32_t assoc;
    uint8_t local[16];
    uint8_t remote[16];
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t instance;
    pid_t pid;
    int state;
} SocketEntry;

typedef struct {
    uint64_t udp_in_no_ports;
    uint64_t udp_in_errors;
    uint64_t udp_in_dgrams;
    uint64_t udp_out_dgrams;
    SocketEntry **udp_arr;
    size_t udp_len;
    size_t udp_max;

    enum TCPRtoAlgorithm tcp_rto_algo;
    uint32_t tcp_rto_min;
    uint32_t tcp_rto_max;
    int32_t tcp_max_conn;
    uint32_t tcp_cur_estab;
    uint64_t tcp_active_open;
    uint64_t tcp_passive_open;
    uint64_t tcp_attempt_fails;
    uint64_t tcp_estab_reset;
    uint64_t tcp_in_segs;
    uint64_t tcp_out_segs;
    uint64_t tcp_retrans_segs;
    uint64_t tcp_in_errs;
    uint64_t tcp_out_rsts;
    SocketEntry **tcp_arr;
    size_t tcp_len;
    size_t tcp_max;

    uint64_t sctp_curr_estab;
    uint64_t sctp_active_estabs;
    uint64_t sctp_passive_estabs;
    uint64_t sctp_aborteds;
    uint64_t sctp_shutdowns;
    uint64_t sctp_out_of_blues;
    uint64_t sctp_checksum_errors;
    uint64_t sctp_out_ctrl_chunks;
    uint64_t sctp_out_order_chunks;
    uint64_t sctp_out_unorder_chunks;
    uint64_t sctp_in_ctrl_chunks;
    uint64_t sctp_in_order_chunks;
    uint64_t sctp_in_unorder_chunks;
    uint64_t sctp_frag_usr_msgs;
    uint64_t sctp_reasm_usr_msgs;
    uint64_t sctp_out_sctp_packs;
    uint64_t sctp_in_sctp_packs;
    uint64_t sctp_discontinuity_time;
    enum SCTPRtoAlgorithm sctp_rto_algo;
    uint32_t sctp_rto_min;
    uint32_t sctp_rto_max;
    uint32_t sctp_rto_initial;
    int      sctp_max_assocs;
    uint32_t sctp_val_cookie_life;
    uint32_t sctp_max_init_retr;
    SocketEntry **sctp_arr;
    size_t sctp_len;
    size_t sctp_max;
} SocketStats;

/**
 * @internal
 * get_socket_stats - returns the current socket statistics
 *
 * @return socket statistics
 */
SocketStats *get_socket_stats(void);

#endif /* SRC_SNMP_MIB_IP_SOCKET_CACHE_H_ */
