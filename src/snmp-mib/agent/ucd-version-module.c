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
#include <stdio.h>
#include <time.h>
#include <sys/sysinfo.h>

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-agent/snmpd.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/ucd-version-module.h"

enum UCDVersionMIBObjects {
    VERSION_INDEX = 1,
    VERSION_TAG = 2,
    VERSION_DATE = 3,
    VERSION_CDATE = 4,
    VERSION_IDENT = 5,
    VERSION_CONFIGURE_OPTIONS = 6,
    VERSION_CLEAR_CACHE = 10,
    VERSION_UPDATE_CONFIG = 11,
    VERSION_RESTART_AGENT = 12,
    VERSION_SAVE_PERSISTENT_DATA = 13,
    VERSION_DO_DEBUGGING = 20
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case VERSION_INDEX: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case VERSION_TAG: {
            SET_OCTET_STRING_RESULT(binding, strdup(GIT_TAG), strlen(GIT_TAG));
            break;
        }

        case VERSION_DATE: {
            SET_OCTET_STRING_RESULT(binding, strdup(GIT_DATE), strlen(GIT_DATE));
            break;
        }

        case VERSION_CDATE: {
            time_t curtime;
            if (time(&curtime) == -1)
                return GENERAL_ERROR;
            char *buf = malloc(26);
            if (buf == NULL)
                return GENERAL_ERROR;
            if (ctime_r(&curtime, buf) == NULL) {
                free(buf);
                return GENERAL_ERROR;
            }
            SET_OCTET_STRING_BIND(binding, buf, strnlen(buf, 26) - 1);
            break;
        }

        case VERSION_IDENT: {
            SET_OCTET_STRING_RESULT(binding,
                strdup(PACKAGE_STRING), strlen(PACKAGE_STRING));
            break;
        }

        case VERSION_CONFIGURE_OPTIONS: {
            SET_OCTET_STRING_RESULT(binding,
                strdup(AGENT_CONF_OPTIONS), strlen(AGENT_CONF_OPTIONS));
            break;
        }

        case VERSION_CLEAR_CACHE:
        case VERSION_UPDATE_CONFIG:
        case VERSION_RESTART_AGENT:
        case VERSION_SAVE_PERSISTENT_DATA: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case VERSION_DO_DEBUGGING: {
            SET_INTEGER_BIND(binding, debug_logging_enabled());
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
    switch (id) {
        case VERSION_CLEAR_CACHE: {
            if (dry_run) {
                return validate_boolean_value(binding);
            } else if (binding->value.integer) {
                get_mib_cache(fetch_empty_cache, free, INT32_MAX);
            }
            break;
        }

        case VERSION_UPDATE_CONFIG: {
            if (dry_run) {
                return validate_boolean_value(binding);
            } else if (binding->value.integer) {
                if (load_configuration())
                    return GENERAL_ERROR;
            }
            break;
        }

        case VERSION_RESTART_AGENT: {
            if (dry_run) {
                return validate_boolean_value(binding);
            }
            break;
        }

        case VERSION_SAVE_PERSISTENT_DATA: {
            if (dry_run) {
                return validate_boolean_value(binding);
            }
            break;
        }

        case VERSION_DO_DEBUGGING: {
            if (dry_run) {
                return validate_boolean_value(binding);
            } else {
                set_debug_logging(binding->value.integer);
            }
            break;
        }

        default: {
            return NOT_WRITABLE;
        }
    }

    return NO_ERROR;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_ucd_version_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, VERSION_INDEX,
            VERSION_DO_DEBUGGING - VERSION_INDEX + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_UNUSED, LEAF_UNUSED, LEAF_UNUSED, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_UNUSED, LEAF_UNUSED,
            LEAF_UNUSED, LEAF_UNUSED, LEAF_UNUSED, LEAF_UNUSED, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_UCD_VERSION);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
