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

#include <stddef.h>
#include <unistd.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/snmp-stats-module.h"

enum SNMPStatsMIBObjects {
    SNMP_IN_PKTS = 1,
    SNMP_OUT_PKTS = 2,
    SNMP_IN_BAD_VERSIONS = 3,
    SNMP_IN_BAD_COMMUNITY_NAMES = 4,
    SNMP_IN_BAD_COMMUNITY_USES = 5,
    SNMP_IN_ASN_PARSE_ERRS = 6,
    SNMP_IN_BAD_TYPES = 7,
    SNMP_IN_TOO_BIGS = 8,
    SNMP_IN_NO_SUCH_NAMES = 9,
    SNMP_IN_BAD_VALUES = 10,
    SNMP_IN_READ_ONLYS = 11,
    SNMP_IN_GEN_ERRS = 12,
    SNMP_IN_TOTAL_REQ_VARS = 13,
    SNMP_IN_TOTAL_SET_VARS = 14,
    SNMP_IN_GET_REQUESTS = 15,
    SNMP_IN_GET_NEXTS = 16,
    SNMP_IN_SET_REQUESTS = 17,
    SNMP_IN_GET_RESPONSES = 18,
    SNMP_IN_TRAPS = 19,
    SNMP_OUT_TOO_BIGS = 20,
    SNMP_OUT_NO_SUCH_NAMES = 21,
    SNMP_OUT_BAD_VALUES = 22,
    SNMP_OUT_READ_ONLY = 23,
    SNMP_OUT_GEN_ERRS = 24,
    SNMP_OUT_GET_REQUESTS = 25,
    SNMP_OUT_GET_NEXTS = 26,
    SNMP_OUT_SET_REQUESTS = 27,
    SNMP_OUT_GET_RESPONSES = 28,
    SNMP_OUT_TRAPS = 29,
    SNMP_ENABLE_AUTHEN_TRAPS = 30,
    SNMP_SILENT_DROPS = 31,
    SNMP_PROXY_DROPS = 32
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch(id) {
        case SNMP_IN_PKTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_pkts);
            break;
        }

        case SNMP_OUT_PKTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_pkts);
            break;
        }

        case SNMP_IN_BAD_VERSIONS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_bad_versions);
            break;
        }

        case SNMP_IN_BAD_COMMUNITY_NAMES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_bad_community_names);
            break;
        }

        case SNMP_IN_BAD_COMMUNITY_USES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_bad_community_uses);
            break;
        }

        case SNMP_IN_ASN_PARSE_ERRS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_asn_parse_errs);
            break;
        }

        case SNMP_IN_BAD_TYPES: {
            SET_UNSIGNED_BIND(binding, 0);
            break;
        }

        case SNMP_IN_TOO_BIGS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_too_big);
            break;
        }

        case SNMP_IN_NO_SUCH_NAMES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_no_such_names);
            break;
        }

        case SNMP_IN_BAD_VALUES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_bad_values);
            break;
        }

        case SNMP_IN_READ_ONLYS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_read_only);
            break;
        }

        case SNMP_IN_GEN_ERRS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_gen_errs);
            break;
        }

        case SNMP_IN_TOTAL_REQ_VARS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_total_req_vars);
            break;
        }

        case SNMP_IN_TOTAL_SET_VARS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_total_set_vars);
            break;
        }

        case SNMP_IN_GET_REQUESTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_get_requests);
            break;
        }

        case SNMP_IN_GET_NEXTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_get_nexts);
            break;
        }

        case SNMP_IN_SET_REQUESTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_set_requests);
            break;
        }

        case SNMP_IN_GET_RESPONSES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_get_responses);
            break;
        }

        case SNMP_IN_TRAPS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_in_traps);
            break;
        }

        case SNMP_OUT_TOO_BIGS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_too_big);
            break;
        }

        case SNMP_OUT_NO_SUCH_NAMES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_no_such_names);
            break;
        }

        case SNMP_OUT_BAD_VALUES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_bad_values);
            break;
        }

        case SNMP_OUT_READ_ONLY: {
            SET_UNSIGNED_BIND(binding, 0);
            break;
        }

        case SNMP_OUT_GEN_ERRS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_gen_errs);
            break;
        }

        case SNMP_OUT_GET_REQUESTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_get_requests);
            break;
        }

        case SNMP_OUT_GET_NEXTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_get_nexts);
            break;
        }

        case SNMP_OUT_SET_REQUESTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_set_requests);
            break;
        }

        case SNMP_OUT_GET_RESPONSES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_get_responses);
            break;
        }

        case SNMP_OUT_TRAPS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_out_traps);
            break;
        }

        case SNMP_ENABLE_AUTHEN_TRAPS: {
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case SNMP_SILENT_DROPS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->snmp_silent_drops);
            break;
        }

        case SNMP_PROXY_DROPS: {
            SET_UNSIGNED_BIND(binding, 0);
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

MibModule *init_snmp_stats_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, SNMP_IN_PKTS,
            SNMP_PROXY_DROPS - SNMP_IN_PKTS + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_MIB2,11);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
