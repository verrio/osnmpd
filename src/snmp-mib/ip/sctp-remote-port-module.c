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

#define SCTP_REMOTE_PORT_OID  SNMP_OID_SCTP_OBJECTS,7

enum SCTPLookupRemPortTableColumns {
    SCTP_LOOKUP_REM_PORT_START_TIME = 1
};

static SocketEntry *get_socket_entry(SubOID *row, size_t row_len, int next_row)
{
    SocketStats *stats = get_socket_stats();
    if (stats == NULL)
        return NULL;

    SocketEntry **entry = stats->sctp_arr;
    size_t len = stats->sctp_len;

    uint32_t port_offset = 0;
    uint32_t assoc_offset = 0;

    if (!next_row) {
        if (row_len != 2)
            return NULL;
        port_offset = row[0];
        assoc_offset = row[1];
    } else if (row_len > 1) {
        port_offset = row[0];
        assoc_offset = row[1] + 1;
    } else if (row_len > 0) {
        port_offset = row[0];
    }

    SocketEntry *sup = NULL;
    for (int i = 0; i < len; i++) {
        SocketEntry *socket = entry[i];

        if (socket->remote_port < port_offset)
            continue;
        if (socket->remote_port == port_offset && socket->assoc < assoc_offset)
            continue;

        if (sup == NULL || socket->remote_port < sup->remote_port ||
            (socket->remote_port == sup->remote_port && socket->assoc < sup->assoc)) {
            sup = socket;
        }
    }

    if (!next_row && sup != NULL &&
        (sup->assoc != assoc_offset || sup->remote_port != port_offset))
        return NULL;
    return sup;
}

DEF_METHOD(get_column, SnmpErrorStatus, SingleTableMibModule, SingleTableMibModule,
    int column, SubOID *row, size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    SocketEntry *socket = get_socket_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, socket);
    SET_TIME_TICKS_BIND(binding, 0);
    INSTANCE_FOUND_INT_ROW2(next_row, SNMP_OID_SCTP_OBJECTS, 7,
            SCTP_LOOKUP_REM_PORT_START_TIME, socket->remote_port, socket->assoc)
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

MibModule *init_sctp_remote_port_module(void)
{
    SingleTableMibModule *module = malloc(sizeof(SingleTableMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_table_module(module,
        SCTP_LOOKUP_REM_PORT_START_TIME, SCTP_LOOKUP_REM_PORT_START_TIME)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SCTP_REMOTE_PORT_OID, 1);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleTableMibModule, get_column);
    SET_METHOD(module, SingleTableMibModule, set_column);
    return &module->public;
}
