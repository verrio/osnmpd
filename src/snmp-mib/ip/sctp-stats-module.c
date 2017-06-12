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
#include "snmp-mib/ip/ip-cache.h"
#include "snmp-mib/ip/socket-cache.h"
#include "snmp-mib/ip/sctp-module.h"

#define SCTP_STATS_OID        SNMP_OID_SCTP_OBJECTS,1
#define SCTP_COMPLIANCE_OID   SNMP_OID_SCTP,2,1,1

static SysOREntry sctp_or_entry = {
    .or_id = {
        .subid = { SCTP_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(SCTP_COMPLIANCE_OID)
    },
    .or_descr = "SCTP-MIB - SCTP statistics",
    .next = NULL
};

enum SCTPStatsMIBObjects {
    SCTP_CURR_ESTAB = 1,
    SCTP_ACTIVE_ESTABS = 2,
    SCTP_PASSIVE_ESTABS = 3,
    SCTP_ABORTEDS = 4,
    SCTP_SHUTDOWNS = 5,
    SCTP_OUT_OF_BLUES = 6,
    SCTP_CHECKSUM_ERRORS = 7,
    SCTP_OUT_CTRL_CHUNKS = 8,
    SCTP_OUT_ORDER_CHUNKS = 9,
    SCTP_OUT_UNORDER_CHUNKS = 10,
    SCTP_IN_CTRL_CHUNKS = 11,
    SCTP_IN_ORDER_CHUNKS = 12,
    SCTP_IN_UNORDER_CHUNKS = 13,
    SCTP_FRAG_USR_MSGS = 14,
    SCTP_REASM_USR_MSGS = 15,
    SCTP_OUT_SCTP_PACKS = 16,
    SCTP_IN_SCTP_PACKS = 17,
    SCTP_DISCONTINUITY_TIME = 18
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
       SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    SocketStats *stats = get_socket_stats();
    if (stats == NULL) {
        return GENERAL_ERROR;
    }

    switch (id) {
        case SCTP_CURR_ESTAB: {
            SET_GAUGE_BIND(binding, LOWER_HALF(stats->sctp_curr_estab));
            break;
        }

        case SCTP_ACTIVE_ESTABS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->sctp_active_estabs));
            break;
        }

        case SCTP_PASSIVE_ESTABS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->sctp_passive_estabs));
            break;
        }

        case SCTP_ABORTEDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->sctp_aborteds));
            break;
        }

        case SCTP_SHUTDOWNS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->sctp_shutdowns));
            break;
        }

        case SCTP_OUT_OF_BLUES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->sctp_out_of_blues));
            break;
        }

        case SCTP_CHECKSUM_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(stats->sctp_checksum_errors));
            break;
        }

        case SCTP_OUT_CTRL_CHUNKS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_out_ctrl_chunks);
            break;
        }

        case SCTP_OUT_ORDER_CHUNKS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_out_order_chunks);
            break;
        }

        case SCTP_OUT_UNORDER_CHUNKS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_out_unorder_chunks);
            break;
        }

        case SCTP_IN_CTRL_CHUNKS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_in_ctrl_chunks);
            break;
        }

        case SCTP_IN_ORDER_CHUNKS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_in_order_chunks);
            break;
        }

        case SCTP_IN_UNORDER_CHUNKS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_in_unorder_chunks);
            break;
        }

        case SCTP_FRAG_USR_MSGS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_frag_usr_msgs);
            break;
        }

        case SCTP_REASM_USR_MSGS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_reasm_usr_msgs);
            break;
        }

        case SCTP_OUT_SCTP_PACKS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_out_sctp_packs);
            break;
        }

        case SCTP_IN_SCTP_PACKS: {
            SET_UNSIGNED64_BIND(binding, stats->sctp_in_sctp_packs);
            break;
        }

        case SCTP_DISCONTINUITY_TIME: {
            SET_TIME_TICKS_BIND(binding, LOWER_HALF(stats->sctp_discontinuity_time));
            break;
        }
    }

    return NO_ERROR;
}

DEF_METHOD(set_scalar, SnmpErrorStatus, SingleLevelMibModule,
       SingleLevelMibModule, int id, SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_sctp_stats_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, SCTP_CURR_ESTAB,
            SCTP_DISCONTINUITY_TIME - SCTP_CURR_ESTAB + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SCTP_STATS_OID);
    SET_OR_ENTRY(module, &sctp_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
