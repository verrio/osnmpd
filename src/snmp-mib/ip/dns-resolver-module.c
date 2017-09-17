#include <arpa/inet.h>
#include <sys/utsname.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/ip/dns-resolver-module.h"

static const char *resolv_ident = "libc";
static const char *resolv_conf = "/etc/resolv.conf";

enum DNSResConfigObjects {
    DNS_RES_CONFIG_IMPLEMENT_IDENT = 1,
    DNS_RES_CONFIG_SERVICE = 2,
    DNS_RES_CONFIG_MAX_CNAMES = 3,
    DNS_RES_CONFIG_SBELT_TABLE = 4,
    DNS_RES_CONFIG_UPTIME = 5,
    DNS_RES_CONFIG_RESET_TIME = 6,
    DNS_RES_CONFIG_RESET = 7
};

enum DNSResConfigSbeltTableColumns {
    DNS_RES_CONFIG_SBELT_ADDR = 1,
    DNS_RES_CONFIG_SBELT_NAME = 2,
    DNS_RES_CONFIG_SBELT_RECURSION = 3,
    DNS_RES_CONFIG_SBELT_PREF = 4,
    DNS_RES_CONFIG_SBELT_SUBTREE = 5,
    DNS_RES_CONFIG_SBELT_CLASS = 6,
    DNS_RES_CONFIG_SBELT_STATUS = 7
};

static int get_name_server(const SubOID *row, const size_t row_len,
    uint8_t *buf, const int next)
{
    FILE *f = fopen(resolv_conf, "r");
    if (f == NULL)
        return -1;

    int found = 0;
    char current[16];
    char line[512];

    while (fgets(line, sizeof(line), f) != NULL) {
        uint8_t server[INET6_ADDRSTRLEN];
        if (sscanf(line, "nameserver %46s", (char *) server) != 1)
            continue;
        struct sockaddr_in sa4;
        struct sockaddr_in6 sa6;
        if (inet_pton(AF_INET6, (char *) server, &(sa6.sin6_addr)) == 1) {
            memcpy(server, sa6.sin6_addr.s6_addr, 16);
        } else if (inet_pton(AF_INET, (char *) server, &(sa4.sin_addr)) == 1) {
            memset(server, 0, sizeof(server));
            memset(server + 10, 0xff, 2);
            server[12] = (ntohl(sa4.sin_addr.s_addr) >> 24) & 0xff;
            server[13] = (ntohl(sa4.sin_addr.s_addr) >> 16) & 0xff;
            server[14] = (ntohl(sa4.sin_addr.s_addr) >> 8) & 0xff;
            server[15] = ntohl(sa4.sin_addr.s_addr) & 0xff;
        } else {
            continue;
        }

        server[16] = 0;
        server[17] = 1;

        if (next) {
            if (row_len > 0 && row[0] > 16) {
                continue;
            } else if (row_len > 0 && row[0] == 16) {
                int larger = 0;
                for (int i = 0; i < min(18, row_len - 1); i++) {
                    if (row[i + 1] > server[i]) {
                        break;
                    } else if (row[i + 1] < server[i]) {
                        larger = 1;
                        break;
                    }
                }
                if (!larger)
                    continue;
            }

            if (found && memcmp(current, server, sizeof(current)) < 0)
                continue;
            memcpy(current, server, sizeof(current));
            found = 1;
        } else {
            if (row_len != 19 || row[0] != 16)
                break;
            int equal = 1;
            for (int i = 0; i < 18; i++) {
                if (row[i + 1] != server[i]) {
                    equal = 0;
                    break;
                }
            }
            if (!equal)
                continue;
            memcpy(current, server, sizeof(current));
            found = 1;
            break;
        }
    }

    fclose(f);
    memcpy(buf, current, sizeof(current));
    return found ? 0 : -1;
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case DNS_RES_CONFIG_IMPLEMENT_IDENT: {
            SET_OCTET_STRING_RESULT(binding,
                strdup(resolv_ident), strlen(resolv_ident));
            break;
        }

        case DNS_RES_CONFIG_SERVICE: {
            /* recursiveOnly */
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case DNS_RES_CONFIG_MAX_CNAMES: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case DNS_RES_CONFIG_UPTIME:
        case DNS_RES_CONFIG_RESET_TIME: {
            SET_GAUGE_BIND(binding, 0);
            break;
        }

        case DNS_RES_CONFIG_RESET: {
            /* running */
            SET_INTEGER_BIND(binding, 4);
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
    return NOT_WRITABLE;
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    if (id != DNS_RES_CONFIG_SBELT_TABLE)
        return GENERAL_ERROR;
    uint8_t addr[16];
    CHECK_INT_FOUND(next_row, get_name_server(row, row_len, addr, next_row));

    switch (column) {
        case DNS_RES_CONFIG_SBELT_ADDR: {
            //TODO wrong type
            SET_OCTET_STRING_RESULT(binding, memdup(addr, 16), 16);
            break;
        }

        case DNS_RES_CONFIG_SBELT_NAME: {
            SET_OCTET_STRING_BIND(binding, NULL, 0);
            break;
        }

        case DNS_RES_CONFIG_SBELT_RECURSION: {
            /* recursive */
            SET_INTEGER_BIND(binding, 2);
            break;
        }

        case DNS_RES_CONFIG_SBELT_PREF: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case DNS_RES_CONFIG_SBELT_SUBTREE: {
            SET_OCTET_STRING_RESULT(binding, strdup("."), 1);
            break;
        }

        case DNS_RES_CONFIG_SBELT_CLASS: {
            /* IN */
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case DNS_RES_CONFIG_SBELT_STATUS: {
            /* active */
            SET_INTEGER_BIND(binding, 1);
            break;
        }
    }

    if (next_row) {
        SET_OID(binding->oid, SNMP_OID_DNS_RESOLVER_CONFIG,
            DNS_RES_CONFIG_SBELT_TABLE, 1, column);
        if (fill_row_index_string(&((binding)->oid), addr, sizeof(addr)))
            return GENERAL_ERROR;
        binding->oid.subid[binding->oid.len++] = 0;
        binding->oid.subid[binding->oid.len++] = 1;
    }
    return NO_ERROR;
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

MibModule *init_dns_resolver_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, DNS_RES_CONFIG_IMPLEMENT_IDENT,
            DNS_RES_CONFIG_RESET - DNS_RES_CONFIG_IMPLEMENT_IDENT + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, DNS_RES_CONFIG_SBELT_STATUS,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_DNS_RESOLVER_CONFIG);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
