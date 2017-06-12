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

#define SCTP_PARAM_OID        SNMP_OID_SCTP_OBJECTS,2

enum SCTPParamsMIBObjects {
    SCTP_RTO_ALGORITHM = 1,
    SCTP_RTO_MIN = 2,
    SCTP_RTO_MAX = 3,
    SCTP_RTO_INITIAL = 4,
    SCTP_MAX_ASSOCS = 5,
    SCTP_VAL_COOKIE_LIFE = 6,
    SCTP_MAX_INIT_RETR = 7
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
       SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    SocketStats *stats = get_socket_stats();
    if (stats == NULL) {
        return GENERAL_ERROR;
    }

    switch (id) {
        case SCTP_RTO_ALGORITHM: {
            SET_INTEGER_BIND(binding, stats->sctp_rto_algo);
            break;
        }

        case SCTP_RTO_MIN: {
            SET_GAUGE_BIND(binding, stats->sctp_rto_min);
            break;
        }

        case SCTP_RTO_MAX: {
            SET_GAUGE_BIND(binding, stats->sctp_rto_max);
            break;
        }

        case SCTP_RTO_INITIAL: {
            SET_GAUGE_BIND(binding, stats->sctp_rto_initial);
            break;
        }

        case SCTP_MAX_ASSOCS: {
            SET_INTEGER_BIND(binding, stats->sctp_max_assocs);
            break;
        }

        case SCTP_VAL_COOKIE_LIFE: {
            SET_GAUGE_BIND(binding, stats->sctp_val_cookie_life);
            break;
        }

        case SCTP_MAX_INIT_RETR: {
            SET_GAUGE_BIND(binding, stats->sctp_max_init_retr);
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

MibModule *init_sctp_params_module(void)
{
   SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
   if (module == NULL) {
       return NULL;
   } else if (init_single_level_module(module, SCTP_RTO_ALGORITHM,
           SCTP_MAX_INIT_RETR - SCTP_RTO_ALGORITHM + 1,
           LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
           LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
       free(module);
       return NULL;
   }

   SET_PREFIX(module, SCTP_PARAM_OID);
   SET_OR_ENTRY(module, NULL);
   SET_METHOD(module, MibModule, finish_module);
   SET_METHOD(module, SingleLevelMibModule, get_scalar);
   SET_METHOD(module, SingleLevelMibModule, set_scalar);
   return &module->public;
}
