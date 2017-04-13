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

#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/ip/ip-cache.h"
#include "snmp-mib/ip/ip-address-cache.h"
#include "snmp-mib/ip/socket-cache.h"
#include "snmp-mib/ip/tcp-module.h"

#define TCP_COMPLIANCE_OID   SNMP_OID_MIB2,49,2,1,2

static SysOREntry tcp_stats_or_entry = {
    .or_id = {
        .subid = { TCP_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(TCP_COMPLIANCE_OID)
    },
    .or_descr = "TCP-MIB - TCP statistics",
    .next = NULL
};

enum TCPMIBObjects {
    TCP_R_TO_ALGORITHM = 1,
    TCP_R_TO_MIN = 2,
    TCP_R_TO_MAX = 3,
    TCP_MAX_CONN = 4,
    TCP_ACTIVE_OPENS = 5,
    TCP_PASSIVE_OPENS = 6,
    TCP_ATTEMPT_FAILS = 7,
    TCP_ESTAB_RESETS = 8,
    TCP_CURR_ESTAB = 9,
    TCP_IN_SEGS = 10,
    TCP_OUT_SEGS = 11,
    TCP_RETRANS_SEGS = 12,
    TCP_CONN_TABLE = 13,
    TCP_IN_ERRS = 14,
    TCP_OUT_RSTS = 15,
    TCP_HC_IN_SEGS = 17,
    TCP_HC_OUT_SEGS = 18,
    TCP_CONNECTION_TABLE = 19,
    TCP_LISTENER_TABLE = 20
};

enum TCPConnTableColumns {
    TCP_CONN_STATE = 1,
    TCP_CONN_LOCAL_ADDRESS = 2,
    TCP_CONN_LOCAL_PORT = 3,
    TCP_CONN_REM_ADDRESS = 4,
    TCP_CONN_REM_PORT = 5
};

enum TCPConnectionTableColumns {
    TCP_CONNECTION_LOCAL_ADDRESS_TYPE = 1,
    TCP_CONNECTION_LOCAL_ADDRESS = 2,
    TCP_CONNECTION_LOCAL_PORT = 3,
    TCP_CONNECTION_REM_ADDRESSTYPE = 4,
    TCP_CONNECTION_REM_ADDRESS = 5,
    TCP_CONNECTION_REM_PORT = 6,
    TCP_CONNECTION_STATE = 7,
    TCP_CONNECTION_PROCESS = 8
};

enum TCPListenerTableColumns {
    TCP_LISTENER_LOCAL_ADDRESS_TYPE = 1,
    TCP_LISTENER_LOCAL_ADDRESS = 2,
    TCP_LISTENER_LOCAL_PORT = 3,
    TCP_LISTENER_PROCESS = 4
};

static void fill_oid_index(OID *oid, SocketEntry *socket, int type)
{
    if (type > 0) {
        oid->subid[oid->len++] = socket->family;
        oid->subid[oid->len++] = ADDRESS_LENGTH(socket);
    }
    for (int i = 0; i < ADDRESS_LENGTH(socket); i++) {
        oid->subid[oid->len++] = socket->local[i];
    }
    oid->subid[oid->len++] = socket->local_port;
    if (type > 1) {
        return;
    } else if (type > 0) {
        oid->subid[oid->len++] = socket->family;
        oid->subid[oid->len++] = ADDRESS_LENGTH(socket);
    }
    for (int i = 0; i < ADDRESS_LENGTH(socket); i++) {
        oid->subid[oid->len++] = socket->remote[i];
    }
    oid->subid[oid->len++] = socket->remote_port;
}

static SocketEntry *get_socket_entry(int column, SubOID *row, size_t row_len,
        int next_row, int type)
{
    SocketStats *stats = get_socket_stats();
    if (stats == NULL) {
        return NULL;
    }

    SocketEntry **entry = stats->tcp_arr;
    size_t len = stats->tcp_len;

    for (int i = 0; i < len; i++) {
        SocketEntry *socket = entry[i];

        if (type < 1 && socket->family != ADDRESS_IP4) {
            return NULL;
        } else if (type > 1 && socket->state != TCP_STATE_LISTEN) {
            continue;
        }

        OID oid;
        oid.len = 0;
        fill_oid_index(&oid, socket, type);
        switch (cmp_index_to_oid(oid.subid, oid.len, row, row_len)) {
            case -1: {
                if (next_row) {
                    return socket;
                } else {
                    return NULL;
                }
                break;
            }

            case 0: {
                if (!next_row) {
                    return socket;
                }
                break;
            }
        }
    }

    return NULL;
}

static SnmpErrorStatus get_con_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    SocketEntry *socket = get_socket_entry(column, row, row_len, next_row, 0);
    CHECK_INSTANCE_FOUND(next_row, socket);

    switch (column) {
        case TCP_CONN_STATE: {
            SET_INTEGER_BIND(binding, socket->state);
            break;
        }

        case TCP_CONN_LOCAL_ADDRESS: {
            SET_IP4_ADDRESS_BIND(binding, socket->local);
            break;
        }

        case TCP_CONN_LOCAL_PORT: {
            SET_INTEGER_BIND(binding, socket->local_port);
            break;
        }

        case TCP_CONN_REM_ADDRESS: {
            SET_IP4_ADDRESS_BIND(binding, socket->remote);
            break;
        }

        case TCP_CONN_REM_PORT: {
            SET_INTEGER_BIND(binding, socket->remote_port);
            break;
        }
    }

    if (next_row) {
        SET_OID(binding->oid, SNMP_OID_TCP, TCP_CONN_TABLE, 1, column);
        fill_oid_index(&binding->oid, socket, 0);
    }
    return NO_ERROR;
}

static SnmpErrorStatus get_connection_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    SocketEntry *socket = get_socket_entry(column, row, row_len, next_row, 1);
    CHECK_INSTANCE_FOUND(next_row, socket);

    switch (column) {
        case TCP_CONNECTION_LOCAL_ADDRESS_TYPE:
        case TCP_CONNECTION_REM_ADDRESSTYPE: {
            SET_INTEGER_BIND(binding, socket->family);
            break;
        }

        case TCP_CONNECTION_LOCAL_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding, memdup(socket->local,
                    ADDRESS_LENGTH(socket)), ADDRESS_LENGTH(socket));
            break;
        }

        case TCP_CONNECTION_LOCAL_PORT: {
            SET_GAUGE_BIND(binding, socket->local_port);
            break;
        }

        case TCP_CONNECTION_REM_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding, memdup(socket->remote,
                    ADDRESS_LENGTH(socket)), ADDRESS_LENGTH(socket));
            break;
        }

        case TCP_CONNECTION_REM_PORT: {
            SET_GAUGE_BIND(binding, socket->remote_port);
            break;
        }

        case TCP_CONNECTION_STATE: {
            SET_INTEGER_BIND(binding, socket->state);
            break;
        }

        case TCP_CONNECTION_PROCESS: {
            SET_GAUGE_BIND(binding, socket->pid);
            break;
        }
    }

    if (next_row) {
        SET_OID(binding->oid, SNMP_OID_TCP, TCP_CONNECTION_TABLE, 1, column);
        fill_oid_index(&binding->oid, socket, 1);
    }
    return NO_ERROR;
}

static SnmpErrorStatus get_listener_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    SocketEntry *socket = get_socket_entry(column, row, row_len, next_row, 2);
    CHECK_INSTANCE_FOUND(next_row, socket);

    switch (column) {
        case TCP_LISTENER_LOCAL_ADDRESS_TYPE: {
            SET_INTEGER_BIND(binding, socket->family);
            break;
        }

        case TCP_LISTENER_LOCAL_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding, memdup(socket->local,
                    ADDRESS_LENGTH(socket)), ADDRESS_LENGTH(socket));
            break;
        }

        case TCP_LISTENER_LOCAL_PORT: {
            SET_GAUGE_BIND(binding, socket->local_port);
            break;
        }

        case TCP_LISTENER_PROCESS: {
            SET_GAUGE_BIND(binding, socket->pid);
            break;
        }
    }

    if (next_row) {
        SET_OID(binding->oid, SNMP_OID_TCP, TCP_LISTENER_TABLE, 1, column);
        fill_oid_index(&binding->oid, socket, 2);
    }
    return NO_ERROR;
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    SocketStats *stats = get_socket_stats();
    if (stats == NULL) {
        return GENERAL_ERROR;
    }

    switch (id) {
        case TCP_R_TO_ALGORITHM: {
            SET_INTEGER_BIND(binding, stats->tcp_rto_algo);
            break;
        }

        case TCP_R_TO_MIN: {
            SET_INTEGER_BIND(binding, stats->tcp_rto_min);
            break;
        }

        case TCP_R_TO_MAX: {
            SET_INTEGER_BIND(binding, stats->tcp_rto_max);
            break;
        }

        case TCP_MAX_CONN: {
            SET_INTEGER_BIND(binding, stats->tcp_max_conn);
            break;
        }

        case TCP_ACTIVE_OPENS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_active_open));
            break;
        }

        case TCP_PASSIVE_OPENS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_passive_open));
            break;
        }

        case TCP_ATTEMPT_FAILS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_attempt_fails));
            break;
        }

        case TCP_ESTAB_RESETS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_estab_reset));
            break;
        }

        case TCP_CURR_ESTAB: {
            SET_GAUGE_BIND(binding, stats->tcp_cur_estab);
            break;
        }

        case TCP_IN_SEGS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_in_segs));
            break;
        }

        case TCP_OUT_SEGS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_out_segs));
            break;
        }

        case TCP_RETRANS_SEGS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_retrans_segs));
            break;
        }

        case TCP_IN_ERRS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_in_errs));
            break;
        }

        case TCP_OUT_RSTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->tcp_out_rsts));
            break;
        }

        case TCP_HC_IN_SEGS: {
            SET_UNSIGNED64_BIND(binding, stats->tcp_in_segs);
            break;
        }

        case TCP_HC_OUT_SEGS: {
            SET_UNSIGNED64_BIND(binding, stats->tcp_out_segs);
            break;
        }

        default: {
            return GENERAL_ERROR;
        }
    }

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
        case TCP_CONN_TABLE: {
            return get_con_table(column, row, row_len, binding, next_row);
        }

        case TCP_CONNECTION_TABLE: {
            return get_connection_table(column, row, row_len, binding, next_row);
        }

        case TCP_LISTENER_TABLE: {
            return get_listener_table(column, row, row_len, binding, next_row);
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

MibModule *init_tcp_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, TCP_R_TO_ALGORITHM,
            TCP_LISTENER_TABLE - TCP_R_TO_ALGORITHM + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, TCP_CONN_REM_PORT, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_UNUSED, LEAF_SCALAR, LEAF_SCALAR,
            TCP_CONNECTION_PROCESS, TCP_LISTENER_PROCESS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_TCP);
    SET_OR_ENTRY(module, &tcp_stats_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
