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
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <pwd.h>

#include "config.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/system/system-module.h"

/* indication of the set of services that this entity may potentially offer */
#define SYS_SERVICES_ROUTER      (2 << (3-1))
#define SYS_SERVICES_APPLICATION (2 << (4-1)) + (2 << (7-1))

static const char *location_file = "/etc/location";
static const char *ip4_forwarding = "/proc/sys/net/ipv4/conf/all/forwarding";
static const char *ip6_forwarding = "/proc/sys/net/ipv6/conf/all/forwarding";

#define SNMPV2_MIB_COMPLIANCE_OID   SNMP_OID_SNMPMODULES,1,2,1,3

static SysOREntry system_or_entry = {
    .or_id = {
        .subid = { SNMPV2_MIB_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(SNMPV2_MIB_COMPLIANCE_OID)
    },
    .or_descr = "SNMPv2-MIB - MIB module for SNMP entities",
    .next = NULL
};

enum SystemMIBObjects {
    SYS_DESCR = 1,
    SYS_OBJECT_ID = 2,
    SYS_UP_TIME = 3,
    SYS_CONTACT = 4,
    SYS_NAME = 5,
    SYS_LOCATION = 6,
    SYS_SERVICES = 7,
    SYS_OR_LAST_CHANGE = 8,
    SYS_OR_TABLE = 9
};

enum SysORTableColumns {
    SYS_OR_COL_INDEX = 1,
    SYS_OR_COL_ID = 2,
    SYS_OR_COL_DESCR = 3,
    SYS_OR_COL_UPTIME = 4
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case SYS_DESCR: {
            char *buf;
            struct utsname uinfo;
            if (uname(&uinfo) || (buf = malloc(255 * sizeof(uint8_t))) == NULL) {
                return GENERAL_ERROR;
            }
            int written = snprintf(buf, 255, "%s - %s %s %s - %s", uinfo.nodename,
                    uinfo.sysname, uinfo.version, uinfo.release, uinfo.machine);
            SET_OCTET_STRING_BIND(binding, (uint8_t *) buf, min(written, 255));
            break;
        }

        case SYS_OBJECT_ID: {
            SET_OID_BIND(binding, SNMP_OID_ENTERPRISE_MIB);
            break;
        }

        case SYS_UP_TIME: {
            SET_TIME_TICKS_BIND(binding, 100 * get_uptime());
            break;
        }

        case SYS_CONTACT: {
            struct passwd *admin = getpwnam(ADMIN_USER_NAME);
            if (admin == NULL || admin->pw_gecos == NULL) {
                SET_OCTET_STRING_BIND(binding, NULL, 0);
            } else {
                SET_OCTET_STRING_RESULT(binding, strdup(admin->pw_gecos),
                        strlen(admin->pw_gecos));
            }
            break;
        }

        case SYS_NAME: {
            char *buf = malloc(255 * sizeof(char));
            if (buf == NULL) {
                return GENERAL_ERROR;
            } else if (gethostname(buf, 255)) {
                free(buf);
                return GENERAL_ERROR;
            }
            SET_UTF8_STRING_BIND(binding, buf);
            break;
        }

        case SYS_LOCATION: {
            binding->value.octet_string.octets = NULL;
            binding->value.octet_string.len = 0;

            if(access(location_file, F_OK) != -1 &&
               read_from_file(location_file, &binding->value.octet_string.octets,
                    &binding->value.octet_string.len)) {
                return GENERAL_ERROR;
            }

            binding->type = SMI_TYPE_OCTET_STRING;
            break;
        }

        case SYS_SERVICES: {
            uint8_t buf[255];
            uint8_t *buf_ptr = buf;
            size_t buf_len = sizeof(buf);
            int routing = 0;
            if (read_from_file(ip4_forwarding, &buf_ptr, &buf_len)) {
                return GENERAL_ERROR;
            } else if (!memcmp("1", buf, 1)) {
                routing = 1;
            } else if ((buf_len = sizeof(buf))
                && read_from_file(ip6_forwarding, &buf_ptr, &buf_len)) {
                return GENERAL_ERROR;
            } else if (!memcmp("1", buf, 1)) {
                routing = 1;
            }
            SET_INTEGER_BIND(binding, routing ? SYS_SERVICES_APPLICATION +
                    SYS_SERVICES_ROUTER : SYS_SERVICES_APPLICATION);
            break;
        }

        case SYS_OR_LAST_CHANGE: {
            SET_TIME_TICKS_BIND(binding, 0);
            break;
        }
    }

    return NO_ERROR;
}

DEF_METHOD(set_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding, int dry_run)
{
    switch (id) {
        case SYS_NAME: {
            if (dry_run) {
                CHECK_UTF8_STRING(binding, 0, 255);
            } else if (sethostname((char *) binding->value.octet_string.octets,
                    binding->value.octet_string.len)) {
                return GENERAL_ERROR;
            }
            break;
        }

        case SYS_LOCATION: {
            if (dry_run) {
                CHECK_UTF8_STRING(binding, 0, 255);
            } else if (write_to_file(location_file,
                    binding->value.octet_string.octets,
                    binding->value.octet_string.len)) {
                return GENERAL_ERROR;
            }
            break;
        }

        default: {
            return NOT_WRITABLE;
        }
    }

    return NO_ERROR;
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    uint32_t skip_entries = 0;
    if (next_row) {
        if (row_len > 0) {
            skip_entries = row[0];
        }
    } else if (row_len != 1 || row_len < 1) {
        return NO_CREATION;
    } else {
        skip_entries = row[0] - 1;
    }

    SysOREntry *entry = mib_get_or_entries();
    for (int i = 0; entry != NULL && i < skip_entries; entry = entry->next, i++);
    CHECK_INSTANCE_FOUND(next_row, entry);

    switch (column) {
        case SYS_OR_COL_INDEX: {
            SET_INTEGER_BIND(binding, skip_entries + 1);
            break;
        }

        case SYS_OR_COL_ID: {
            COPY_OID_BIND(binding, &entry->or_id);
            break;
        }

        case SYS_OR_COL_DESCR: {
            SET_OCTET_STRING_RESULT(binding, strdup(entry->or_descr),
                    strlen(entry->or_descr));
            break;
        }

        case SYS_OR_COL_UPTIME: {
            SET_TIME_TICKS_BIND(binding, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_SYSTEM_MIB, id, column, skip_entries + 1);
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *index, size_t index_len,
    SnmpVariableBinding *binding, int dry_run)
{
    int i = 0;
    SysOREntry *entry;
    for (entry = mib_get_or_entries(); entry != NULL; entry = entry->next, i++);
    return (index_len != 1 || index[0] > i) ? NO_CREATION : NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_system_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, SYS_DESCR, SYS_OR_TABLE - SYS_DESCR + 1,
        LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
        LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, SYS_OR_COL_UPTIME)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_SYSTEM_MIB);
    SET_OR_ENTRY(module, &system_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
