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
#include "snmp-mib/single-table-module.h"
#include "snmp-mib/ip/ip-address-cache.h"
#include "snmp-mib/ip/socket-cache.h"
#include "snmp-mib/ip/sctp-module.h"

#define SCTP_ASSOC_OID  SNMP_OID_SCTP_OBJECTS,3

enum SCTPAssocTableColumns {
    SCTP_ASSOC_ID = 1,
    SCTP_ASSOC_REM_HOST_NAME = 2,
    SCTP_ASSOC_LOCAL_PORT = 3,
    SCTP_ASSOC_REM_PORT = 4,
    SCTP_ASSOC_REM_PRIM_ADDR_TYPE = 5,
    SCTP_ASSOC_REM_PRIM_ADDR = 6,
    SCTP_ASSOC_HEART_BEAT_INTERVAL = 7,
    SCTP_ASSOC_STATE = 8,
    SCTP_ASSOC_IN_STREAMS = 9,
    SCTP_ASSOC_OUT_STREAMS = 10,
    SCTP_ASSOC_MAX_RETR = 11,
    SCTP_ASSOC_PRIM_PROCESS = 12,
    SCTP_ASSOC_T1_EXPIREDS = 13,
    SCTP_ASSOC_T2_EXPIREDS = 14,
    SCTP_ASSOC_RTX_CHUNKS = 15,
    SCTP_ASSOC_START_TIME = 16,
    SCTP_ASSOC_DISCONTINUITY_TIME = 17
};

static SocketEntry *get_socket_entry(SubOID *row, size_t row_len, int next_row)
{
    SocketStats *stats = get_socket_stats();
    if (stats == NULL)
        return NULL;

    SocketEntry **entry = stats->sctp_arr;
    size_t len = stats->sctp_len;

    uint32_t offset = 1;
    if (!next_row && (row_len != 1 || row[0] < 1))
        return NULL;
    if (row_len > 0) {
        offset = row[0];
        if (next_row)
            offset++;
    }

    for (int i = 0; i < len; i++) {
        SocketEntry *socket = entry[i];

        if (socket->assoc < offset)
            continue;
        if (socket->assoc > offset && !next_row)
            return NULL;
        return socket;
    }

    return NULL;
}

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    SocketEntry *socket = get_socket_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, socket);

    switch (column) {
        case SCTP_ASSOC_ID: {
            SET_GAUGE_BIND(binding, socket->assoc);
            break;
        }

        case SCTP_ASSOC_REM_HOST_NAME: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case SCTP_ASSOC_LOCAL_PORT: {
            SET_GAUGE_BIND(binding, socket->local_port);
            break;
        }

        case SCTP_ASSOC_REM_PORT: {
            SET_GAUGE_BIND(binding, socket->remote_port);
            break;
        }

        case SCTP_ASSOC_REM_PRIM_ADDR_TYPE: {
            SET_INTEGER_BIND(binding, socket->family);
            break;
        }

        case SCTP_ASSOC_REM_PRIM_ADDR: {
            SET_OCTET_STRING_RESULT(binding, memdup(socket->remote,
                ADDRESS_LENGTH(socket)), ADDRESS_LENGTH(socket));
            break;
        }

        case SCTP_ASSOC_HEART_BEAT_INTERVAL: {
            SET_GAUGE_BIND(binding, 0);
            break;
        }

        case SCTP_ASSOC_STATE: {
            SET_INTEGER_BIND(binding, socket->state);
            break;
        }

        case SCTP_ASSOC_IN_STREAMS:
        case SCTP_ASSOC_OUT_STREAMS:
        case SCTP_ASSOC_MAX_RETR: {
            SET_GAUGE_BIND(binding, 0);
            break;
        }

        case SCTP_ASSOC_PRIM_PROCESS: {
            SET_GAUGE_BIND(binding, socket->pid);
            break;
        }

        case SCTP_ASSOC_T1_EXPIREDS:
        case SCTP_ASSOC_T2_EXPIREDS:
        case SCTP_ASSOC_RTX_CHUNKS: {
            SET_UNSIGNED_BIND(binding, 0);
            break;
        }

        case SCTP_ASSOC_START_TIME:
        case SCTP_ASSOC_DISCONTINUITY_TIME: {
            SET_TIME_TICKS_BIND(binding, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_SCTP_OBJECTS, 3, column, socket->assoc);
}

DEF_METHOD(set_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *index, size_t index_len, SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleTableMibModule)
{
    finish_single_table_module(this);
}

MibModule *init_sctp_assoc_module(void)
{
    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module,
        SCTP_ASSOC_ID, SCTP_ASSOC_DISCONTINUITY_TIME)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SCTP_ASSOC_OID, 1);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
