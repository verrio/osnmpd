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

#include <arpa/inet.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <inttypes.h>
#include <stdio.h>

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/target-module.h"

#define TARGET_MIB_OID      SNMP_OID_SNMPMODULES,12,1
#define TARGET_MIB_COMPLIANCE_OID   SNMP_OID_SNMPMODULES,12,3,1,1

/* single instance index */
SubOID target_table_idx[] = { 117, 112, 115, 116, 114, 101, 97, 109 };
size_t target_table_idx_len = OID_LENGTH(target_table_idx);

/* message processing and security model 3 */
#define MPV3    3
#define MSECV3  3

static const char *table_index_ref = "upstream";
#define TARGET_TAG_LIST     "upstream monitoring"

/* transport domains */
#define TRANSPORT_DOMAIN_UDP_IP4 SNMP_OID_MIB2,100,1,1
#define TRANSPORT_DOMAIN_UDP_IP6 SNMP_OID_MIB2,100,1,2
#define TRANSPORT_DOMAIN_UDP_DNS SNMP_OID_MIB2,100,1,14

enum TargetAddressType {
    TARGET_IP4,
    TARGET_IP6,
    TARGET_DNS
};

static SysOREntry target_or_entry = {
    .or_id = {
        .subid = { TARGET_MIB_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(TARGET_MIB_COMPLIANCE_OID)
    },
    .or_descr = "SNMP-TARGET-MIB - MIB module for managing notification targets",
    .next = NULL
};

enum TargetMIBObjects {
    SNMP_TARGET_SPIN_LOCK = 1,
    SNMP_TARGET_ADDRESS_TABLE = 2,
    SNMP_TARGET_PARAMS_TABLE = 3,
    SNMP_UNAVAILABLE_CONTEXTS = 4,
    SNMP_UNKNOWN_CONTEXTS = 5
};

enum TargetAddressTableColumns {
    SNMP_TARGET_ADDR_NAME = 1,
    SNMP_TARGET_ADDR_TDOMAIN = 2,
    SNMP_TARGET_ADDR_TADDRESS = 3,
    SNMP_TARGET_ADDR_TIMEOUT = 4,
    SNMP_TARGET_ADDR_RETRY_COUNT = 5,
    SNMP_TARGET_ADDR_TAG_LIST = 6,
    SNMP_TARGET_ADDR_PARAMS = 7,
    SNMP_TARGET_ADDR_STORAGE_TYPE = 8,
    SNMP_TARGET_ADDR_ROW_STATUS = 9
};

enum ParametersTableColumns {
    SNMP_TARGET_PARAMS_NAME = 1,
    SNMP_TARGET_PARAMS_MP_MODEL = 2,
    SNMP_TARGET_PARAMS_SECURITY_MODEL = 3,
    SNMP_TARGET_PARAMS_SECURITY_NAME = 4,
    SNMP_TARGET_PARAMS_SECURITY_LEVEL = 5,
    SNMP_TARGET_PARAMS_STORAGE_TYPE = 6,
    SNMP_TARGET_PARAMS_ROW_STATUS = 7
};

static enum TargetAddressType get_target_address_type(void)
{
    char *host = get_trap_configuration()->destination;
    uint8_t addr[16];

    if (host == NULL ||
        inet_pton(AF_INET6, host, addr) == 1) {
        return TARGET_IP6;
    } else if (inet_pton(AF_INET, host, addr) == 1) {
        return TARGET_IP4;
    } else {
        return TARGET_DNS;
    }
}

static SnmpErrorStatus get_address_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    /* single instance */
    int cmp = cmp_index_to_oid(target_table_idx, target_table_idx_len, row, row_len);
    if (next_row && cmp >= 0) {
        binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
        return NO_ERROR;
    } else if (!next_row && cmp) {
        binding->type = SMI_EXCEPT_NO_SUCH_INSTANCE;
        return NO_ERROR;
    }

    switch (column) {
        case SNMP_TARGET_ADDR_TDOMAIN: {
            switch (get_target_address_type()) {
                case TARGET_IP6: {
                    SET_OID_BIND(binding, TRANSPORT_DOMAIN_UDP_IP6);
                    break;
                }

                case TARGET_IP4: {
                    SET_OID_BIND(binding, TRANSPORT_DOMAIN_UDP_IP4);
                    break;
                }

                case TARGET_DNS: {
                    SET_OID_BIND(binding, TRANSPORT_DOMAIN_UDP_DNS);
                    break;
                }
            }
            break;
        }

        case SNMP_TARGET_ADDR_TADDRESS: {
            char buf[512];
            if (get_trap_configuration()->destination == NULL) {
                buf[0] = '\0';
            } else if (get_target_address_type() == TARGET_IP6) {
                snprintf(buf, sizeof(buf), "[%s]:%" PRIu16,
                    get_trap_configuration()->destination, get_trap_configuration()->port);
            } else {
                snprintf(buf, sizeof(buf), "%s:%" PRIu16,
                    get_trap_configuration()->destination, get_trap_configuration()->port);
            }
            SET_OCTET_STRING_RESULT(binding, strdup(buf), strlen(buf));
            break;
        }

        case SNMP_TARGET_ADDR_TIMEOUT: {
            /* timeout in 0.01 seconds */
            SET_INTEGER_BIND(binding, get_trap_configuration()->timeout * 100);
            break;
        }

        case SNMP_TARGET_ADDR_RETRY_COUNT: {
            SET_INTEGER_BIND(binding, get_trap_configuration()->retries);
            break;
        }

        case SNMP_TARGET_ADDR_TAG_LIST: {
            SET_OCTET_STRING_RESULT(binding, strdup(TARGET_TAG_LIST),
                    strlen(TARGET_TAG_LIST));
            break;
        }

        case SNMP_TARGET_ADDR_NAME:
        case SNMP_TARGET_ADDR_PARAMS: {
            SET_OCTET_STRING_RESULT(binding, strdup(table_index_ref),
                    strlen(table_index_ref));
            break;
        }

        case SNMP_TARGET_ADDR_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case SNMP_TARGET_ADDR_ROW_STATUS: {
            /* active/notInService */
            SET_INTEGER_BIND(binding, get_trap_configuration()->enabled ? 1 : 2);
            break;
        }
    }

    INSTANCE_FOUND_OID_ROW(next_row, TARGET_MIB_OID, SNMP_TARGET_ADDRESS_TABLE,
            column, target_table_idx, target_table_idx_len);
}

static SnmpErrorStatus get_params_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    /* single instance */
    int cmp = cmp_index_to_oid(target_table_idx, target_table_idx_len, row, row_len);
    if (next_row && cmp >= 0) {
        binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
        return NO_ERROR;
    } else if (!next_row && cmp) {
        binding->type = SMI_EXCEPT_NO_SUCH_INSTANCE;
        return NO_ERROR;
    }

    switch (column) {
        case SNMP_TARGET_PARAMS_NAME: {
            SET_OCTET_STRING_RESULT(binding, strdup(table_index_ref),
                    strlen(table_index_ref));
            break;
        }

        case SNMP_TARGET_PARAMS_MP_MODEL: {
            SET_INTEGER_BIND(binding, MPV3);
            break;
        }

        case SNMP_TARGET_PARAMS_SECURITY_MODEL: {
            SET_INTEGER_BIND(binding, MSECV3);
            break;
        }

        case SNMP_TARGET_PARAMS_SECURITY_NAME: {
            if (get_trap_configuration()->user != -1) {
                char *user = get_user_configuration(get_trap_configuration()
                        ->user)->name;
                SET_OCTET_STRING_RESULT(binding, strdup(user), strlen(user));
            } else {
                SET_OCTET_STRING_BIND(binding, NULL, 0);
            }
            break;
        }

        case SNMP_TARGET_PARAMS_SECURITY_LEVEL: {
            int level = 0;
            if (get_trap_configuration()->user != -1) {
                level = get_user_configuration(get_trap_configuration()->user)
                        ->security_level;
            }
            SET_INTEGER_BIND(binding, level);
            break;
        }

        case SNMP_TARGET_PARAMS_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case SNMP_TARGET_PARAMS_ROW_STATUS: {
            /* active/notInService */
            SET_INTEGER_BIND(binding, get_trap_configuration()->enabled ? 1 : 2);
            break;
        }
    }

    INSTANCE_FOUND_OID_ROW(next_row, TARGET_MIB_OID, SNMP_TARGET_PARAMS_TABLE,
            column, target_table_idx, target_table_idx_len);
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case SNMP_TARGET_SPIN_LOCK: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case SNMP_UNAVAILABLE_CONTEXTS: {
            /* all engine ID mismatches are counted as unknown engines */
            SET_UNSIGNED_BIND(binding, 0);
            break;
        }

        case SNMP_UNKNOWN_CONTEXTS: {
            SET_UNSIGNED_BIND(binding, get_statistics()->usm_stats_unknown_engine_ids);
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

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    switch (id) {
        case SNMP_TARGET_ADDRESS_TABLE: {
            return get_address_table(column, row, row_len, binding, next_row);
        }

        case SNMP_TARGET_PARAMS_TABLE: {
            return get_params_table(column, row, row_len, binding, next_row);
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

MibModule *init_target_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, SNMP_TARGET_SPIN_LOCK,
        SNMP_UNKNOWN_CONTEXTS - SNMP_TARGET_SPIN_LOCK + 1, LEAF_SCALAR,
        SNMP_TARGET_ADDR_ROW_STATUS, SNMP_TARGET_PARAMS_ROW_STATUS,
        LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, TARGET_MIB_OID);
    SET_OR_ENTRY(module, &target_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
