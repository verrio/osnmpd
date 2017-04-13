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
#include "snmp-mib/agent/usm-stats-module.h"

#define USM_STATS_COMPLIANCE_OID   SNMP_OID_USM_MIB,2,1,1

static SysOREntry usm_stats_or_entry = {
    .or_id = {
        .subid = { USM_STATS_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(USM_STATS_COMPLIANCE_OID)
    },
    .or_descr = "SNMP-USER-BASED-SM-MIB - management information definitions " \
            "for the user-based security model",
    .next = NULL
};

enum UsmStatsMIBObjects {
    USM_STATS_UNSUPPORTED_SEC_LEVELS = 1,
    USM_STATS_NOT_IN_TIME_WINDOWS = 2,
    USM_STATS_UNKNOWN_USER_NAMES = 3,
    USM_STATS_UNKNOWN_ENGINE_IDS = 4,
    USM_STATS_WRONG_DIGESTS = 5,
    USM_STATS_DECRYPTION_ERRORS = 6
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case USM_STATS_UNSUPPORTED_SEC_LEVELS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->usm_stats_unsupported_sec_levels);
            break;
        }

        case USM_STATS_NOT_IN_TIME_WINDOWS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->usm_stats_not_in_time_windows);
            break;
        }

        case USM_STATS_UNKNOWN_USER_NAMES: {
            SET_UNSIGNED_BIND(binding, get_statistics()->usm_stats_unknown_user_names);
            break;
        }

        case USM_STATS_UNKNOWN_ENGINE_IDS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->usm_stats_unknown_engine_ids);
            break;
        }

        case USM_STATS_WRONG_DIGESTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->usm_stats_wrong_digests);
            break;
        }

        case USM_STATS_DECRYPTION_ERRORS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->usm_stats_decryption_errors);
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

MibModule *init_usm_stats_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, USM_STATS_UNSUPPORTED_SEC_LEVELS,
        USM_STATS_DECRYPTION_ERRORS - USM_STATS_UNSUPPORTED_SEC_LEVELS + 1,
        LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
        LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_USM_MIB,1,1);
    SET_OR_ENTRY(module, &usm_stats_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
