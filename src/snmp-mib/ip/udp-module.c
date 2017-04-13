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
#include "snmp-mib/ip/udp-module.h"

#define UDP_COMPLIANCE_OID   SNMP_OID_MIB2,50,2,1,2

static SysOREntry udp_stats_or_entry = {
    .or_id = {
        .subid = { UDP_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(UDP_COMPLIANCE_OID)
    },
    .or_descr = "UDP-MIB - UDP statistics",
    .next = NULL
};

enum UDPMIBObjects {
    UDP_IN_DATAGRAMS = 1,
    UDP_NO_PORTS = 2,
    UDP_IN_ERRORS = 3,
    UDP_OUT_DATAGRAMS = 4,
    UDP_TABLE = 5,
    UDP_ENDPOINT_TABLE = 7,
    UDP_HC_IN_DATAGRAMS = 8,
    UDP_HC_OUT_DATAGRAMS = 9
};

enum UDPTableColumns {
    UDP_LOCAL_ADDRESS = 1,
    UDP_LOCAL_PORT = 2
};

enum UDPEndpointTableColumns {
    UDP_ENDPOINT_LOCAL_ADDRESS_TYPE = 1,
    UDP_ENDPOINT_LOCAL_ADDRESS = 2,
    UDP_ENDPOINT_LOCAL_PORT = 3,
    UDP_ENDPOINT_REMOTE_ADDRESS_TYPE = 4,
    UDP_ENDPOINT_REMOTE_ADDRESS = 5,
    UDP_ENDPOINT_REMOTE_PORT = 6,
    UDP_ENDPOINT_INSTANCE = 7,
    UDP_ENDPOINT_PROCESS = 8
};

static void fill_oid(OID *oid, int column, SocketEntry *socket, int prefix)
{
    oid->len = 0;
    if (prefix) {
        SET_OID(*oid, SNMP_OID_UDP, UDP_ENDPOINT_TABLE, 1, column);
    }
    oid->subid[oid->len++] = socket->family;
    oid->subid[oid->len++] = ADDRESS_LENGTH(socket);
    for (int i = 0; i < ADDRESS_LENGTH(socket); i++) {
        oid->subid[oid->len++] = socket->local[i];
    }
    oid->subid[oid->len++] = socket->local_port;
    oid->subid[oid->len++] = socket->family;
    oid->subid[oid->len++] = ADDRESS_LENGTH(socket);
    for (int i = 0; i < ADDRESS_LENGTH(socket); i++) {
        oid->subid[oid->len++] = socket->remote[i];
    }
    oid->subid[oid->len++] = socket->remote_port;
    oid->subid[oid->len++] = socket->instance;
}

static SocketEntry *get_socket_entry(int column, SubOID *row, size_t row_len,
        int next_row, int ip4_only)
{
    SocketStats *stats = get_socket_stats();
    if (stats == NULL) {
        return NULL;
    }

    SocketEntry **entry = stats->udp_arr;
    size_t len = stats->udp_len;

    for (int i = 0; i < len; i++) {
        SocketEntry *socket = entry[i];

        if (ip4_only) {
            if (socket->family != ADDRESS_IP4) {
                return NULL;
            } else if (!next_row && row_len != 5) {
                return NULL;
            }

            switch (cmp_fixed_index_to_array(socket->local, 4,
                    row, min(row_len,4))) {
                case -1: {
                    if (next_row) {
                        return socket;
                    } else {
                        return NULL;
                    }
                }

                case 0: {
                    if (next_row) {
                        if (row_len < 4 || row[4] < socket->local_port) {
                            return socket;
                        }
                    } else if (row[4] == socket->local_port) {
                        return socket;
                    } else if (row[4] < socket->local_port) {
                        return NULL;
                    }
                    break;
                }
            }
        } else {
            OID oid;
            fill_oid(&oid, column, socket, 0);

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
    }

    return NULL;
}

static SnmpErrorStatus get_udp_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    SocketEntry *socket = get_socket_entry(column, row, row_len, next_row, 1);
    CHECK_INSTANCE_FOUND(next_row, socket);

    switch (column) {
        case UDP_LOCAL_ADDRESS: {
            SET_IP4_ADDRESS_BIND(binding, socket->local);
            break;
        }

        case UDP_LOCAL_PORT: {
            SET_INTEGER_BIND(binding, socket->local_port);
            break;
        }
    }

    if (next_row) {
        SET_OID(binding->oid, SNMP_OID_UDP, UDP_TABLE, 1, column,
                socket->local[0], socket->local[1], socket->local[2],
                socket->local[3], socket->local_port);
    }
    return NO_ERROR;
}

static SnmpErrorStatus get_udp_endpoint_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    SocketEntry *socket = get_socket_entry(column, row, row_len, next_row, 0);
    CHECK_INSTANCE_FOUND(next_row, socket);

    switch (column) {
        case UDP_ENDPOINT_LOCAL_ADDRESS_TYPE:
        case UDP_ENDPOINT_REMOTE_ADDRESS_TYPE: {
            SET_INTEGER_BIND(binding, socket->family);
            break;
        }

        case UDP_ENDPOINT_LOCAL_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding, memdup(socket->local,
                    ADDRESS_LENGTH(socket)), ADDRESS_LENGTH(socket));
            break;
        }

        case UDP_ENDPOINT_LOCAL_PORT: {
            SET_GAUGE_BIND(binding, socket->local_port);
            break;
        }

        case UDP_ENDPOINT_REMOTE_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding, memdup(socket->remote,
                    ADDRESS_LENGTH(socket)), ADDRESS_LENGTH(socket));
            break;
        }

        case UDP_ENDPOINT_REMOTE_PORT: {
            SET_GAUGE_BIND(binding, socket->remote_port);
            break;
        }

        case UDP_ENDPOINT_INSTANCE: {
            SET_GAUGE_BIND(binding, socket->instance);
            break;
        }

        case UDP_ENDPOINT_PROCESS: {
            SET_GAUGE_BIND(binding, socket->pid);
            break;
        }
    }

    if (next_row) {
        fill_oid(&binding->oid, column, socket, 1);
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
        case UDP_IN_DATAGRAMS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->udp_in_dgrams));
            break;
        }

        case UDP_NO_PORTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->udp_in_no_ports));
            break;
        }

        case UDP_IN_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->udp_in_errors));
            break;
        }

        case UDP_OUT_DATAGRAMS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->udp_out_dgrams));
            break;
        }

        case UDP_HC_IN_DATAGRAMS: {
            SET_UNSIGNED64_BIND(binding, stats->udp_in_dgrams);
            break;
        }

        case UDP_HC_OUT_DATAGRAMS: {
            SET_UNSIGNED64_BIND(binding, stats->udp_out_dgrams);
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
        case UDP_TABLE: {
            return get_udp_table(column, row, row_len, binding, next_row);
        }

        case UDP_ENDPOINT_TABLE: {
            return get_udp_endpoint_table(column, row, row_len, binding, next_row);
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

MibModule *init_udp_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, UDP_IN_DATAGRAMS,
            UDP_HC_OUT_DATAGRAMS - UDP_IN_DATAGRAMS + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            UDP_LOCAL_PORT, LEAF_UNUSED, UDP_ENDPOINT_PROCESS,
            LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_UDP);
    SET_OR_ENTRY(module, &udp_stats_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
