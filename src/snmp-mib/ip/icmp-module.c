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
#include "snmp-mib/ip/icmp-module.h"

#define IP_VER_MIN 1
#define IP_VER_MAX 2

enum ICMPMIBObjects {
    ICMP_STATS_TABLE = 29,
    ICMP_MSG_STATS_TABLE = 30
};

enum ICMPStatsTableColumns {
    ICMP_STATS_IP_VERSION = 1,
    ICMP_STATS_IN_MSG = 2,
    ICMP_STATS_IN_ERRORS = 3,
    ICMP_STATS_OUT_MSGS = 4,
    ICMP_STATS_OUT_ERRORS = 5
};

enum ICMPMsgStatsTableColumns {
    ICMP_MSG_STATS_IP_VERSION = 1,
    ICMP_MSG_STATS_TYPE = 2,
    ICMP_MSG_STATS_IN_PKTS = 3,
    ICMP_MSG_STATS_OUT_PKTS = 4
};

static SnmpErrorStatus get_icmp_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    IpStatistics *ip_stats = get_ip_statistics();
    if (ip_stats == NULL) {
        return GENERAL_ERROR;
    }

    const uint32_t row_min[] = { IP_VER_MIN };
    const uint32_t row_max[] = { IP_VER_MAX };
    uint32_t ip_version[] = { 0 };
    CHECK_INT_FOUND(next_row, search_int_indices(1, row_min, row_max,
        ip_version, row, row_len, next_row));
    IcmpStatsTableEntry *entry = ip_version[0] == 1 ?
        &ip_stats->icmp4 : &ip_stats->icmp6;
    switch (column) {
        case ICMP_STATS_IP_VERSION: {
            SET_INTEGER_BIND(binding, ip_version[0]);
            break;
        }

        case ICMP_STATS_IN_MSG: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(entry->in_msg));
            break;
        }

        case ICMP_STATS_IN_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(entry->in_err));
            break;
        }

        case ICMP_STATS_OUT_MSGS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(entry->out_msg));
            break;
        }

        case ICMP_STATS_OUT_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(entry->out_err));
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_ICMP, ICMP_STATS_TABLE,
        column, ip_version[0]);
}

static SnmpErrorStatus get_icmp_msg_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    IpStatistics *ip_stats = get_ip_statistics();
    if (ip_stats == NULL) {
        return GENERAL_ERROR;
    }

    const uint32_t row_min[] = { IP_VER_MIN, 0 };
    const uint32_t row_max[] = { IP_VER_MAX, MAX_ICMP_TYPES - 1 };
    uint32_t new_row[] = { 0, 0 };
    CHECK_INT_FOUND(next_row, search_int_indices(2, row_min, row_max,
            new_row, row, row_len, next_row));
    IcmpMsgStatsTableEntry *entry = new_row[0] == 1 ?
        &ip_stats->icmp4_msg[new_row[1]] : &ip_stats->icmp6_msg[new_row[1]];

    switch (column) {
        case ICMP_MSG_STATS_IP_VERSION: {
            SET_INTEGER_BIND(binding, new_row[0]);
            break;
        }

        case ICMP_MSG_STATS_TYPE: {
            SET_INTEGER_BIND(binding, new_row[1]);
            break;
        }

        case ICMP_MSG_STATS_IN_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(entry->in_pkts));
            break;
        }

        case ICMP_MSG_STATS_OUT_PKTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(entry->out_pkts));
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW2(next_row, SNMP_OID_ICMP, ICMP_MSG_STATS_TABLE,
        column, new_row[0], new_row[1]);
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    switch (id) {
        case ICMP_STATS_TABLE: {
            return get_icmp_table(column, row, row_len, binding, next_row);
        }

        case ICMP_MSG_STATS_TABLE: {
            return get_icmp_msg_table(column, row, row_len, binding, next_row);
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

MibModule *init_icmp_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, ICMP_STATS_TABLE,
            ICMP_MSG_STATS_TABLE - ICMP_STATS_TABLE + 1,
            ICMP_STATS_OUT_ERRORS, ICMP_MSG_STATS_OUT_PKTS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_ICMP);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
