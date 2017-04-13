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
#include <sys/utsname.h>
#include <unistd.h>
#include <stdio.h>

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/system/system-module.h"

#define APPLICATION_MIB_COMPLIANCE_OID  SNMP_OID_NETWORK_APPLICATION_MIB,3,2,1

static SysOREntry application_or_entry = {
    .or_id = {
        .subid = { APPLICATION_MIB_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(APPLICATION_MIB_COMPLIANCE_OID)
    },
    .or_descr = "NETWORK-SERVICES-MIB - MIB module describing network service applications",
    .next = NULL
};

enum SystemMIBObjects {
    APPL_TABLE = 1,
    ASSOC_TABLE = 2
};

enum ApplicationTableColumns {
    APPL_INDEX = 1,
    APPL_NAME = 2,
    APPL_DIRECTORY_NAME = 3,
    APPL_VERSION = 4,
    APPL_UPTIME = 5,
    APPL_OPER_STATUS = 6,
    APPL_LAST_CHANGE = 7,
    APPL_INBOUND_ASSOCIATIONS = 8,
    APPL_OUTBOUND_ASSOCIATIONS = 9,
    APPL_ACCUMULATED_INBOUND_ASSOCIATIONS = 10,
    APPL_ACCUMULATED_OUTBOUND_ASSOCIATIONS = 11,
    APPL_LAST_INBOUND_ACTIVITY = 12,
    APPL_LAST_OUTBOUND_ACTIVITY = 13,
    APPL_REJECTED_INBOUND_ASSOCIATIONS = 14,
    APPL_FAILED_OUTBOUND_ASSOCIATIONS = 15,
    APPL_DESCRIPTION = 16,
    APPL_URL = 17
};

enum AssociationTableColumns {
    ASSOC_INDEX = 1,
    ASSOC_REMOTE_APPLICATION = 2,
    ASSOC_APPLICATION_PROTOCOL = 3,
    ASSOC_APPLICATION_TYPE = 4,
    ASSOC_DURATION = 5
};

static SnmpErrorStatus get_application_column(int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    uint32_t skip_entries = 0;
    if (next_row) {
        if (row_len > 0) {
            skip_entries = row[0];
        }
    } else if (row_len != 1) {
        binding->type = SMI_EXCEPT_NO_SUCH_INSTANCE;
        return NO_ERROR;
    } else {
        skip_entries = row[0] - 1;
    }

    int i;
    MibApplicationModule *app = mib_get_app_modules();
    for (i = 0; app != NULL && i < skip_entries; app = app->next, i++);
    CHECK_INSTANCE_FOUND(next_row, app);

    switch (column) {
        case APPL_INDEX: {
            SET_INTEGER_BIND(binding, i+1);
            break;
        }

        case APPL_NAME: {
            char *name = app->get_name();
            SET_OCTET_STRING_RESULT(binding,
                (uint8_t *) strdup(name), strlen(name));
            break;
        }

        case APPL_DIRECTORY_NAME: {
            /* no directory service available */
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case APPL_VERSION: {
            char *version = app->get_version();
            SET_OCTET_STRING_RESULT(binding,
                (uint8_t *) strdup(version), strlen(version));
            break;
        }

        case APPL_UPTIME: {
            uint32_t app_uptime = app->get_uptime();
            uint32_t snmp_start = get_start_time();
            SET_TIME_TICKS_BIND(binding, app_uptime < snmp_start ?
                    0 : (app_uptime - snmp_start) * 100);
            break;
        }

        case APPL_OPER_STATUS: {
            SET_INTEGER_BIND(binding, app->get_oper_state());
            break;
        }

        case APPL_LAST_CHANGE: {
            uint32_t last_change = app->get_last_change();
            uint32_t snmp_start = get_start_time();
            SET_TIME_TICKS_BIND(binding, last_change < snmp_start ?
                    0 : (last_change - snmp_start) * 100);
            break;
        }

        case APPL_INBOUND_ASSOCIATIONS: {
            SET_GAUGE_BIND(binding, app->get_inbound_assoc());
            break;
        }

        case APPL_OUTBOUND_ASSOCIATIONS: {
            SET_GAUGE_BIND(binding, app->get_outbound_assoc());
            break;
        }

        case APPL_ACCUMULATED_INBOUND_ASSOCIATIONS: {
            SET_UNSIGNED_BIND(binding, app->get_acc_inbound_assoc());
            break;
        }

        case APPL_ACCUMULATED_OUTBOUND_ASSOCIATIONS: {
            SET_UNSIGNED_BIND(binding, app->get_acc_outbound_assoc());
            break;
        }

        case APPL_LAST_INBOUND_ACTIVITY: {
            uint32_t last_inbound = app->get_last_inbound();
            uint32_t snmp_start = get_start_time();
            SET_TIME_TICKS_BIND(binding, last_inbound < snmp_start ?
                    0 : (last_inbound - snmp_start) * 100);
            break;
        }

        case APPL_LAST_OUTBOUND_ACTIVITY: {
            uint32_t last_outbound = app->get_last_outbound();
            uint32_t snmp_start = get_start_time();
            SET_TIME_TICKS_BIND(binding, last_outbound < snmp_start ?
                    0 : (last_outbound - snmp_start) * 100);
            break;
        }

        case APPL_REJECTED_INBOUND_ASSOCIATIONS: {
            SET_UNSIGNED_BIND(binding, app->get_acc_failed_inbound_assoc());
            break;
        }

        case APPL_FAILED_OUTBOUND_ASSOCIATIONS: {
            SET_UNSIGNED_BIND(binding, app->get_acc_failed_outbound_assoc());
            break;
        }

        case APPL_DESCRIPTION: {
            char *descr = app->get_description();
            SET_OCTET_STRING_RESULT(binding,
                (uint8_t *) strdup(descr), strlen(descr));
            break;
        }

        case APPL_URL: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_NETWORK_APPLICATION_MIB,
        APPL_TABLE, column, skip_entries + 1);
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    switch (id) {
        case APPL_TABLE: {
            return get_application_column(column, row, row_len, binding, next_row);
        }

        case ASSOC_TABLE: {
            /* TODO: add application association table */
            binding->type = next_row ? SMI_EXCEPT_END_OF_MIB_VIEW : SMI_EXCEPT_NO_SUCH_INSTANCE;
            return NO_ERROR;
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
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_application_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, APPL_TABLE,
        ASSOC_TABLE - APPL_TABLE + 1, APPL_URL, ASSOC_DURATION)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_NETWORK_APPLICATION_MIB);
    SET_OR_ENTRY(module, &application_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
