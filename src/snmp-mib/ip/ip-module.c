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
#include <arpa/inet.h>
#include <sys/socket.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/ip/ip-address-cache.h"
#include "snmp-mib/ip/ip-cache.h"
#include "snmp-mib/ip/if-cache.h"
#include "snmp-mib/ip/ip-module.h"
#include "snmp-mib/ip/ip-traffic-stats.h"

#define IP_COMPLIANCE_OID   SNMP_OID_MIB2,48,2,1,2

static SysOREntry ip_stats_or_entry = {
    .or_id = {
        .subid = { IP_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(IP_COMPLIANCE_OID)
    },
    .or_descr = "IP-MIB - IPv4/IPv6 statistics",
    .next = NULL
};

enum IPMIBObjects {
    IP_FORWARDING = 1,
    IP_DEFAULT_TTL = 2,
    IP_IN_RECEIVES = 3,
    IP_IN_HDR_ERRORS = 4,
    IP_IN_ADDR_ERRORS  = 5,
    IP_FORW_DATAGRAMS = 6,
    IP_IN_UNKNOWNPROTOS = 7,
    IP_IN_DISCARDS = 8,
    IP_IN_DELIVERS = 9,
    IP_OUT_REQUESTS = 10,
    IP_OUT_DISCARDS = 11,
    IP_OUT_NO_ROUTES = 12,
    IP_REASM_TIMEOUT = 13,
    IP_REASM_REQDS = 14,
    IP_REASM_OKS = 15,
    IP_REASM_FAILS = 16,
    IP_FRAG_OKS = 17,
    IP_FRAG_FAILS = 18,
    IP_FRAG_CREATES = 19,
    IP_ADDR_TABLE = 20,
    IP_NET_TO_MEDIA_TABLE = 22,
    IP_ROUTING_DISCARDS = 23,
    IP6_IP_FORWARDING = 25,
    IP6_IP_DEFAULT_HOP_LIMIT = 26,
    IP4_INTERFACE_TABLE_LAST_CHANGE = 27,
    IP4_INTERFACE_TABLE = 28,
    IP6_INTERFACE_TABLE_LAST_CHANGE = 29,
    IP6_INTERFACE_TABLE = 30,
    IP_TRAFFIC_STATS = 31,
    IP_ADDRESS_PREFIX_TABLE = 32,
    IP_ADDRESS_SPIN_LOCK = 33,
    IP_ADDRESS_TABLE = 34,
    IP_NET_TO_PHYSICAL_TABLE = 35,
    IP6_SCOPE_ZONE_INDEX_TABLE = 36,
    IP_DEFAULT_ROUTER_TABLE = 37,
    IP6_ROUTER_ADVERT_SPIN_LOCK = 38,
    IP6_ROUTER_ADVERT_TABLE = 39
};

enum IPAddrTableColumns {
    IP_AD_ENT_ADDR = 1,
    IP_AD_ENT_IF_INDEX = 2,
    IP_AD_ENT_NET_MASK = 3,
    IP_AD_ENT_BCAST_ADDR = 4,
    IP_AD_ENT_REASM_MAX_SIZE = 5
};

enum IPNetToMediaTableColumns {
    IP_NET_TO_MEDIA_IF_INDEX = 1,
    IP_NET_TO_MEDIA_PHYS_ADDRESS = 2,
    IP_NET_TO_MEDIA_NET_ADDRESS = 3,
    IP_NET_TO_MEDIA_TYPE = 4
};

enum IP4InterfaceTableColumns {
    IP4_INTERFACE_IF_INDEX = 1,
    IP4_INTERFACE_REASM_MAX_SIZE = 2,
    IP4_INTERFACE_ENABLE_STATUS = 3,
    IP4_INTERFACE_RETRANSMIT_TIME = 4
};

enum IP6InterfaceTableColumns {
    IP6_INTERFACE_IF_INDEX = 1,
    IP6_INTERFACE_REASM_MAX_SIZE = 2,
    IP6_INTERFACE_IDENTIFIER = 3,
    IP6_INTERFACE_ENABLE_STATUS = 5,
    IP6_INTERFACE_REACHABLE_TIME = 6,
    IP6_INTERFACE_RETRANSMIT_TIME = 7,
    IP6_INTERFACE_FORWARDING = 8
};

enum IPAddressPrefixTableColumns {
    IP_ADDRESS_PREFIX_IF_INDEX = 1,
    IP_ADDRESS_PREFIX_TYPE = 2,
    IP_ADDRESS_PREFIX_PREFIX = 3,
    IP_ADDRESS_PREFIX_LENGTH = 4,
    IP_ADDRESS_PREFIX_ORIGIN = 5,
    IP_ADDRESS_PREFIX_ON_LINK_FLAG = 6,
    IP_ADDRESS_PREFIX_AUTONOMOUSFLAG = 7,
    IP_ADDRESS_PREFIX_ADV_PREFERRED_LIFETIME = 8,
    IP_ADDRESS_PREFIX_ADV_VALID_LIFETIME = 9
};

enum IPAddressTableColumns {
    IP_ADDRESS_ADDR_TYPE = 1,
    IP_ADDRESS_ADDR = 2,
    IP_ADDRESS_IF_INDEX = 3,
    IP_ADDRESS_TYPE = 4,
    IP_ADDRESS_PREFIX = 5,
    IP_ADDRESS_ORIGIN = 6,
    IP_ADDRESS_STATUS = 7,
    IP_ADDRESS_CREATED = 8,
    IP_ADDRESS_LAST_CHANGED = 9,
    IP_ADDRESS_ROW_STATUS = 10,
    IP_ADDRESS_STORAGE_TYPE = 11
};

enum IPNetToPhysicalTableColumns {
    IP_NET_TO_PHYSICAL_IF_INDEX = 1,
    IP_NET_TO_PHYSICAL_NET_ADDRESS_TYPE = 2,
    IP_NET_TO_PHYSICAL_NET_ADDRESS = 3,
    IP_NET_TO_PHYSICAL_PHYS_ADDRESS = 4,
    IP_NET_TO_PHYSICAL_LAST_UPDATED = 5,
    IP_NET_TO_PHYSICAL_TYPE = 6,
    IP_NET_TO_PHYSICAL_STATE = 7,
    IP_NET_TO_PHYSICAL_ROW_STATUS = 8
};

enum IP6ScopeZoneIndexTableColumns {
    IP6_SCOPE_ZONE_INDEX_IF_INDEX = 1,
    IP6_SCOPE_ZONE_INDEX_LINK_LOCAL = 2,
    IP6_SCOPE_ZONE_INDEX_3 = 3,
    IP6_SCOPE_ZONE_INDEX_ADMIN_LOCAL = 4,
    IP6_SCOPE_ZONE_INDEX_SITE_LOCAL = 5,
    IP6_SCOPE_ZONE_INDEX_6 = 6,
    IP6_SCOPE_ZONE_INDEX_7 = 7,
    IP6_SCOPE_ZONE_INDEX_ORGANIZATION_LOCAL = 8,
    IP6_SCOPE_ZONE_INDEX_9 = 9,
    IP6_SCOPE_ZONE_INDEX_A = 10,
    IP6_SCOPE_ZONE_INDEX_B = 11,
    IP6_SCOPE_ZONE_INDEX_C = 12,
    IP6_SCOPE_ZONE_INDEX_D = 13
};

enum IPDefaultRouterTableColumns {
    IP_DEFAULT_ROUTER_ADDRESS_TYPE = 1,
    IP_DEFAULT_ROUTER_ADDRESS = 2,
    IP_DEFAULT_ROUTER_IF_INDEX = 3,
    IP_DEFAULT_ROUTER_LIFETIME = 4,
    IP_DEFAULT_ROUTER_PREFERENCE = 5
};

enum IP6RouterAdvertTableColumns {
    IP6_ROUTER_ADVERT_IF_INDEX = 1,
    IP6_ROUTER_ADVERT_SEND_ADVERTS = 2,
    IP6_ROUTER_ADVERT_MAX_INTERVAL = 3,
    IP6_ROUTER_ADVERT_MIN_INTERVAL = 4,
    IP6_ROUTER_ADVERT_MANAGED_FLAG = 5,
    IP6_ROUTER_ADVERT_OTHER_CONFIG_FLAG = 6,
    IP6_ROUTER_ADVERT_LINK_MTU = 7,
    IP6_ROUTER_ADVERT_REACHABLE_TIME = 8,
    IP6_ROUTER_ADVERT_RETRANSMIT_TIME = 9,
    IP6_ROUTER_ADVERT_CUR_HOP_LIMIT = 10,
    IP6_ROUTER_ADVERT_DEFAULT_LIFETIME = 11,
    IP6_ROUTER_ADVERT_ROW_STATUS = 12
};

static int has_zero_address(const IfaceEntry *iface)
{
    for (int i = 0; i < iface->address_len; i++) {
        if (iface->address[i]) {
            return 0;
        }
    }

    return 1;
}

static IpAddressEntry *get_ip_address(const SubOID *row,
        const size_t row_len, const int include_type, const int next_row)
{
    for (IpAddressEntry *ip_address = get_ip_address_list();
            ip_address != NULL; ip_address = ip_address->next) {
        /* address type */
        if (include_type) {
            if (row_len < 1 || row[0] < ip_address->family) {
                return next_row ? ip_address : NULL;
            } else if (row[0] > ip_address->family) {
                continue;
            }
        } else if (ip_address->family != ADDRESS_IP4) {
            continue;
        }

        /* address */
        int cmp;
        if (include_type) {
            cmp = cmp_index_to_array(ip_address->address,
                ADDRESS_LENGTH(ip_address), row + 1, row_len - 1);
        } else {
            cmp = cmp_fixed_index_to_array(ip_address->address, 4, row, row_len);
        }
        if (cmp < 0 && next_row) {
            return ip_address;
        } else if (cmp == 0 && !next_row) {
            return ip_address;
        }
    }

    return NULL;
}

static IpToPhysicalAddressEntry *get_ip_to_phy_entry(const SubOID *row,
        const size_t row_len, const int include_type, const int next_row)
{
    for (IpToPhysicalAddressEntry *cur = get_ip_to_phy_address_list();
        cur != NULL; cur = cur->next) {
        if (!include_type && cur->family != ADDRESS_IP4) {
            continue;
        }

        /* iface index */
        if (row_len < 1 || row[0] < cur->iface) {
            return next_row ? cur : NULL;
        } else if (row[0] > cur->iface) {
            continue;
        }

        /* address type index */
        if (include_type) {
            if (row_len < 2 || row[1] < cur->family) {
                return next_row ? cur : NULL;
            } else if (row[1] > cur->family) {
                continue;
            }
        }

        /* address index */
        int cmp;
        if (include_type) {
            cmp = cmp_index_to_array(cur->address,
                    ADDRESS_LENGTH(cur), row + 2, row_len - 2);
        } else {
            cmp = cmp_fixed_index_to_array(cur->address, 4, row + 1, row_len - 1);
        }
        if (cmp < 0 && next_row) {
            return cur;
        } else if (cmp == 0 && !next_row) {
            return cur;
        }
    }

    return NULL;
}

static IfaceEntry *get_iface_entry(const SubOID *row,
        const size_t row_len, const int next_row)
{
    int index = 0;
    if (row_len > 1) {
        if (next_row) {
            index = row[0];
        } else {
            return NULL;
        }
    } else if (row_len > 0) {
        index = row[0];
    }

    for (IfaceEntry *cur = get_iface_list(); cur != NULL; cur = cur->next) {
        if (cur->id > index) {
            return next_row ? cur : NULL;
        } else if (cur->id == index && !next_row) {
            return cur;
        }
    }

    return NULL;
}

static void get_prefix_ref(const IpAddressEntry *address, OID *oid,
        int row_only, int column)
{
    if (address->prefix == 0 || (address->prefix >> 3) == ADDRESS_LENGTH(address)) {
        if (row_only) {
            oid->len = 0;
        } else {
            oid->len = 2;
            oid->subid[0] = 0;
            oid->subid[1] = 0;
        }
    } else {
        if (!row_only) {
            SET_OID(*oid, SNMP_OID_IP,IP_ADDRESS_PREFIX_TABLE,1,column);
        }

        oid->subid[oid->len++] = address->iface;
        oid->subid[oid->len++] = address->family;
        oid->subid[oid->len++] = ADDRESS_LENGTH(address);

        int rem = address->prefix;
        for (int i = 0; i < ADDRESS_LENGTH(address); i++) {
            if (rem > 8) {
                oid->subid[oid->len++] = 0xff & address->address[i];
                rem -= 8;
            } else if (rem > 0) {
                oid->subid[oid->len++] =
                    0xff & (address->address[i] & (0xff << (8 - rem)));
                rem = 0;
            } else {
                oid->subid[oid->len++] = 0x00;
            }
        }

        oid->subid[oid->len++] = address->prefix;
    }
}

static IpAddressEntry *get_ip_prefix(const SubOID *row,
        const size_t row_len, const int next_row)
{
    IpAddressEntry *cur = NULL;
    OID cur_oid;

    for (IpAddressEntry *c = get_ip_address_list(); c != NULL; c = c->next) {
        OID oid;
        oid.len = 0;

        get_prefix_ref(c, &oid, 1, 0);

        if (oid.len < 1) {
            continue;
        }
        switch (cmp_index_to_oid(oid.subid, oid.len, row, row_len)) {
            case -1: {
                if (next_row && (cur == NULL || compare_OID(&oid, &cur_oid) < 0)) {
                    memcpy(&cur_oid, &oid, sizeof(OID));
                    cur = c;
                }
                break;
            }

            case 0: {
                if (!next_row) {
                    return c;
                }
                break;
            }
        }
    }

    return cur;
}

static IpDefaultRouteEntry *get_default_route(const SubOID *row,
        const size_t row_len, const int next_row)
{
    for (IpDefaultRouteEntry *c = get_ip_default_route_list(); c != NULL; c = c->next) {
        /* address type index */
        if (row_len < 1 || row[0] < c->family) {
            return next_row ? c : NULL;
        } else if (row[0] > c->family) {
            continue;
        }

        /* address */
        if (row_len < 2 || row[1] < ADDRESS_LENGTH(c)) {
            return next_row ? c : NULL;
        } else if (row[1] > ADDRESS_LENGTH(c)) {
            continue;
        } else {
            switch (cmp_fixed_index_to_array(c->address,
                ADDRESS_LENGTH(c), row + 2, min(row_len - 2, row[1]))) {
                case -1: {
                    return next_row ? c : NULL;
                }

                case 1: {
                    continue;
                }
            }
        }

        /* iface */
        if (row_len < 3 + ADDRESS_LENGTH(c) || row[ADDRESS_LENGTH(c) + 2] < c->iface) {
            return next_row ? c : NULL;
        } else if (!next_row && row[ADDRESS_LENGTH(c) + 2] == c->iface) {
            return c;
        }
    }

    return NULL;
}

static SnmpErrorStatus get_ip_addr_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    IpAddressEntry *ip_address = get_ip_address(row, row_len, 0, next_row);
    CHECK_INSTANCE_FOUND(next_row, ip_address);

    switch (column) {
        case IP_AD_ENT_ADDR: {
            SET_IP4_ADDRESS_BIND(binding, ip_address->address);
            break;
        }

        case IP_AD_ENT_IF_INDEX: {
            SET_INTEGER_BIND(binding, ip_address->iface);
            break;
        }

        case IP_AD_ENT_NET_MASK: {
            binding->type = SMI_TYPE_IP_ADDRESS;
            set_netmask(ip_address->prefix, binding->value.ip_address, 4);
            break;
        }

        case IP_AD_ENT_BCAST_ADDR: {
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case IP_AD_ENT_REASM_MAX_SIZE: {
            SET_INTEGER_BIND(binding, 0xffff);
            break;
        }
    }

    INSTANCE_FOUND_FIXED_STRING_ROW(next_row, SNMP_OID_IP, IP_ADDR_TABLE,
        column, ip_address->address, 4);
}

static SnmpErrorStatus get_ip_address_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    IpAddressEntry *ip_address = get_ip_address(row, row_len, 1, next_row);
    CHECK_INSTANCE_FOUND(next_row, ip_address);

    switch (column) {
        case IP_ADDRESS_ADDR_TYPE: {
            SET_INTEGER_BIND(binding, ip_address->family);
            break;
        }

        case IP_ADDRESS_ADDR: {
            SET_OCTET_STRING_RESULT(binding, memdup(ip_address->address,
                ADDRESS_LENGTH(ip_address)), ADDRESS_LENGTH(ip_address));
            break;
        }

        case IP_ADDRESS_IF_INDEX: {
            SET_INTEGER_BIND(binding, ip_address->iface);
            break;
        }

        case IP_ADDRESS_TYPE: {
            SET_INTEGER_BIND(binding, ip_address->address_type);
            break;
        }

        case IP_ADDRESS_PREFIX: {
            binding->type = SMI_TYPE_OID;
            get_prefix_ref(ip_address, &binding->value.oid,
                    0, IP_ADDRESS_PREFIX_PREFIX);
            break;
        }

        case IP_ADDRESS_ORIGIN: {
            SET_INTEGER_BIND(binding, ip_address->origin);
            break;
        }

        case IP_ADDRESS_STATUS: {
            SET_INTEGER_BIND(binding, ip_address->status);
            break;
        }

        case IP_ADDRESS_CREATED: {
            SET_TIME_TICKS_BIND(binding,
                100 * rebase_duration(ip_address->created / 100));
            break;
        }

        case IP_ADDRESS_LAST_CHANGED: {
            SET_TIME_TICKS_BIND(binding,
                100 * rebase_duration(ip_address->last_changed / 100));
            break;
        }

        case IP_ADDRESS_ROW_STATUS: {
            /* active */
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case IP_ADDRESS_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }
    }

    INSTANCE_FOUND_INT_OCTET_STRING_ROW(next_row, SNMP_OID_IP, IP_ADDRESS_TABLE,
        column, ip_address->family, ip_address->address, ADDRESS_LENGTH(ip_address))
}

static SnmpErrorStatus get_ip_prefix_table(int column, SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    IpAddressEntry *ip_address = get_ip_prefix(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, ip_address);

    switch (column) {
        case IP_ADDRESS_PREFIX_IF_INDEX: {
            SET_INTEGER_BIND(binding, ip_address->iface);
            break;
        }

        case IP_ADDRESS_PREFIX_TYPE: {
            SET_INTEGER_BIND(binding, ip_address->family);
            break;
        }

        case IP_ADDRESS_PREFIX_PREFIX: {
            uint8_t *prefix = memdup(ip_address->address, ADDRESS_LENGTH(ip_address));
            if (prefix == NULL) {
                return GENERAL_ERROR;
            }

            int offset = ip_address->prefix >> 3;
            int rem = ip_address->prefix % 8;
            for (int i = offset; i < ADDRESS_LENGTH(ip_address); i++) {
                if (rem > 0) {
                    prefix[i] = ip_address->address[i] & (0xff << (8 - rem));
                    rem = 0;
                } else {
                    prefix[i] = 0x00;
                }
            }
            SET_OCTET_STRING_BIND(binding, prefix, ADDRESS_LENGTH(ip_address));
            break;
        }

        case IP_ADDRESS_PREFIX_LENGTH: {
            SET_GAUGE_BIND(binding, ip_address->prefix);
            break;
        }

        case IP_ADDRESS_PREFIX_ORIGIN: {
            SET_INTEGER_BIND(binding, ip_address->origin);
            break;
        }

        case IP_ADDRESS_PREFIX_ON_LINK_FLAG: {
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case IP_ADDRESS_PREFIX_AUTONOMOUSFLAG: {
            SET_INTEGER_BIND(binding, 2);
            break;
        }

        case IP_ADDRESS_PREFIX_ADV_PREFERRED_LIFETIME: {
            SET_GAUGE_BIND(binding, ip_address->preferred);
            break;
        }

        case IP_ADDRESS_PREFIX_ADV_VALID_LIFETIME: {
            SET_GAUGE_BIND(binding, ip_address->valid);
            break;
        }
    }

    if (next_row) {
        get_prefix_ref(ip_address, &binding->oid, 0, column);
    }

    return NO_ERROR;
}

static SnmpErrorStatus get_scope_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    IpAddressEntry *ip_address = NULL;
    for (IpAddressEntry *c = get_ip_address_list(); c != NULL; c = c->next) {
        if (c->family != ADDRESS_IP6 || c->origin != IP_ADDRESS_ORIGIN_LINKLAYER) {
            continue;
        } else if (ip_address != NULL && ip_address->iface < c->iface) {
            continue;
        }

        if (next_row) {
            if (row_len < 1 || c->iface > row[0]) {
                ip_address = c;
            }
        } else if (row_len != 1) {
            break;
        } else if (c->iface == row[0]) {
            ip_address = c;
            break;
        }
    }

    CHECK_INSTANCE_FOUND(next_row, ip_address);

    switch (column) {
        case IP6_SCOPE_ZONE_INDEX_IF_INDEX: {
            SET_INTEGER_BIND(binding, ip_address->iface);
            break;
        }

        case IP6_SCOPE_ZONE_INDEX_LINK_LOCAL: {
            SET_GAUGE_BIND(binding, ip_address->iface);
            break;
        }

        case IP6_SCOPE_ZONE_INDEX_3:
        case IP6_SCOPE_ZONE_INDEX_ADMIN_LOCAL:
        case IP6_SCOPE_ZONE_INDEX_SITE_LOCAL:
        case IP6_SCOPE_ZONE_INDEX_6:
        case IP6_SCOPE_ZONE_INDEX_7:
        case IP6_SCOPE_ZONE_INDEX_ORGANIZATION_LOCAL:
        case IP6_SCOPE_ZONE_INDEX_9:
        case IP6_SCOPE_ZONE_INDEX_A:
        case IP6_SCOPE_ZONE_INDEX_B:
        case IP6_SCOPE_ZONE_INDEX_C:
        case IP6_SCOPE_ZONE_INDEX_D: {
            SET_GAUGE_BIND(binding, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_IP,
        IP6_SCOPE_ZONE_INDEX_TABLE, column, ip_address->iface)
}

static SnmpErrorStatus get_ip_to_media_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    IpToPhysicalAddressEntry *address = get_ip_to_phy_entry(row, row_len, 0, next_row);
    CHECK_INSTANCE_FOUND(next_row, address);

    switch (column) {
        case IP_NET_TO_MEDIA_IF_INDEX: {
            SET_INTEGER_BIND(binding, address->iface);
            break;
        }

        case IP_NET_TO_MEDIA_PHYS_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding,
                memdup(address->physical, address->physical_len), address->physical_len);
            break;
        }

        case IP_NET_TO_MEDIA_NET_ADDRESS: {
            SET_IP4_ADDRESS_BIND(binding, address->address);
            break;
        }

        case IP_NET_TO_MEDIA_TYPE: {
            SET_INTEGER_BIND(binding, address->mapping == IP_TO_PHY_TYPE_LOCAL ?
                    IP_TO_PHY_TYPE_STATIC : address->mapping);
            break;
        }
    }

    INSTANCE_FOUND_INT_FIXED_STRING_ROW(next_row, SNMP_OID_IP,
        IP_NET_TO_MEDIA_TABLE, column, address->iface, address->address, 4);
}

static SnmpErrorStatus get_ip_to_phy_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    IpToPhysicalAddressEntry *address = get_ip_to_phy_entry(row, row_len, 1, next_row);
    CHECK_INSTANCE_FOUND(next_row, address);

    switch (column) {
        case IP_NET_TO_PHYSICAL_IF_INDEX: {
            SET_INTEGER_BIND(binding, address->iface);
            break;
        }

        case IP_NET_TO_PHYSICAL_NET_ADDRESS_TYPE: {
            SET_INTEGER_BIND(binding, address->family);
            break;
        }

        case IP_NET_TO_PHYSICAL_NET_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding,
                    memdup(address->address, ADDRESS_LENGTH(address)),
                    ADDRESS_LENGTH(address));
            break;
        }

        case IP_NET_TO_PHYSICAL_PHYS_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding,
                    memdup(address->physical, address->physical_len),
                    address->physical_len);
            break;
        }

        case IP_NET_TO_PHYSICAL_LAST_UPDATED: {
            SET_TIME_TICKS_BIND(binding, 100 * address->last_changed);
            break;
        }

        case IP_NET_TO_PHYSICAL_TYPE: {
            SET_INTEGER_BIND(binding, address->mapping);
            break;
        }

        case IP_NET_TO_PHYSICAL_STATE: {
            SET_INTEGER_BIND(binding, address->state);
            break;
        }

        case IP_NET_TO_PHYSICAL_ROW_STATUS: {
            /* active */
            SET_INTEGER_BIND(binding, 1);
            break;
        }
    }

    INSTANCE_FOUND_INT2_OCTET_STRING_ROW(next_row, SNMP_OID_IP,
            IP_NET_TO_PHYSICAL_TABLE, column, address->iface, address->family,
            address->address, ADDRESS_LENGTH(address))
}

static SnmpErrorStatus get_ip4_iface_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    IfaceEntry *iface = get_iface_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, iface);

    switch (column) {
        case IP4_INTERFACE_IF_INDEX: {
            SET_INTEGER_BIND(binding, iface->id);
            break;
        }

        case IP4_INTERFACE_REASM_MAX_SIZE: {
            SET_INTEGER_BIND(binding, 0xffff);
            break;
        }

        case IP4_INTERFACE_ENABLE_STATUS: {
            SET_INTEGER_BIND(binding, iface->ip4_stats.admin_state);
            break;
        }

        case IP4_INTERFACE_RETRANSMIT_TIME: {
            SET_GAUGE_BIND(binding, iface->ip4_stats.retrans_time);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_IP,
            IP4_INTERFACE_TABLE, column, iface->id)
}

static SnmpErrorStatus get_ip6_iface_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    IfaceEntry *iface = get_iface_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, iface);

    switch (column) {
        case IP6_INTERFACE_IF_INDEX: {
            SET_INTEGER_BIND(binding, iface->id);
            break;
        }

        case IP6_INTERFACE_REASM_MAX_SIZE: {
            SET_GAUGE_BIND(binding, iface->ip6_stats.max_reasm_len);
            break;
        }

        case IP6_INTERFACE_IDENTIFIER: {
            if (has_zero_address(iface)) {
                SET_OCTET_STRING_BIND(binding, NULL, 0);
            } else {
                uint8_t *iden = malloc(8 * sizeof(uint8_t));
                int size = 8;
                if (iden == NULL) {
                    return GENERAL_ERROR;
                } else if (iface->address_len == 6) {
                    memcpy(iden, iface->address, 3);
                    iden[3] = 0xFF;
                    iden[4] = 0xFE;
                    memcpy(iden + 5, iface->address + 3, 3);
                    iden[0] ^= 2;
                } else {
                    size = min(iface->address_len, 8);
                    memcpy(iden, iface->address, size);
                }
                SET_OCTET_STRING_BIND(binding, iden, size);
            }
            break;
        }

        case IP6_INTERFACE_ENABLE_STATUS: {
            SET_INTEGER_BIND(binding, iface->ip6_stats.admin_state);
            break;
        }

        case IP6_INTERFACE_REACHABLE_TIME: {
            SET_GAUGE_BIND(binding, iface->ip6_stats.reachable_time);
            break;
        }

        case IP6_INTERFACE_RETRANSMIT_TIME: {
            SET_GAUGE_BIND(binding, iface->ip6_stats.retrans_time);
            break;
        }

        case IP6_INTERFACE_FORWARDING: {
            SET_INTEGER_BIND(binding, iface->ip6_stats.forwarding);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_IP,
            IP6_INTERFACE_TABLE, column, iface->id)
}

static SnmpErrorStatus get_default_route_table(int column, SubOID *row,
        size_t row_len, SnmpVariableBinding *binding, int next_row)
{
    IpDefaultRouteEntry *route = get_default_route(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, route);

    switch (column) {
        case IP_DEFAULT_ROUTER_ADDRESS_TYPE: {
            SET_INTEGER_BIND(binding, route->family);
            break;
        }

        case IP_DEFAULT_ROUTER_ADDRESS: {
            SET_OCTET_STRING_RESULT(binding, memdup(route->address,
                    ADDRESS_LENGTH(route)), ADDRESS_LENGTH(route));
            break;
        }

        case IP_DEFAULT_ROUTER_IF_INDEX: {
            SET_INTEGER_BIND(binding, route->iface);
            break;
        }

        case IP_DEFAULT_ROUTER_LIFETIME: {
            SET_GAUGE_BIND(binding, route->lifetime);
            break;
        }

        case IP_DEFAULT_ROUTER_PREFERENCE: {
            SET_INTEGER_BIND(binding, route->preference);
            break;
        }
    }

    INSTANCE_FOUND_INT_OCTET_STRING_INT_ROW(next_row, SNMP_OID_IP,
            IP_DEFAULT_ROUTER_TABLE, column, route->family, route->address,
            ADDRESS_LENGTH(route), route->iface)
}

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    IpStatistics *ip_stats = get_ip_statistics();
    if (ip_stats == NULL) {
        return GENERAL_ERROR;
    }

    switch (id) {
        case IP_FORWARDING: {
            SET_INTEGER_BIND(binding, ip_stats->ip4.forwarding);
            break;
        }

        case IP_DEFAULT_TTL: {
            SET_INTEGER_BIND(binding, ip_stats->ip4.default_ttl);
            break;
        }

        case IP_IN_RECEIVES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.in_receives));
            break;
        }

        case IP_IN_HDR_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.in_hdr_errors));
            break;
        }

        case IP_IN_ADDR_ERRORS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.in_addr_errors));
            break;
        }

        case IP_FORW_DATAGRAMS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.in_forw_datagrams));
            break;
        }

        case IP_IN_UNKNOWNPROTOS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.in_unknown_protos));
            break;
        }

        case IP_IN_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.in_discards));
            break;
        }

        case IP_IN_DELIVERS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.in_delivers));
            break;
        }

        case IP_OUT_REQUESTS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.out_requests));
            break;
        }

        case IP_OUT_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.out_discards));
            break;
        }

        case IP_OUT_NO_ROUTES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.out_no_routes));
            break;
        }

        case IP_REASM_TIMEOUT: {
            SET_INTEGER_BIND(binding, LOWER_HALF(ip_stats->ip4.reasm_timeout));
            break;
        }

        case IP_REASM_REQDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.reasm_reqds));
            break;
        }

        case IP_REASM_OKS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.reasm_oks));
            break;
        }

        case IP_REASM_FAILS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.reasm_fails));
            break;
        }

        case IP_FRAG_OKS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.out_frag_oks));
            break;
        }

        case IP_FRAG_FAILS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.out_frag_fails));
            break;
        }

        case IP_FRAG_CREATES: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.out_frag_creates));
            break;
        }

        case IP_ROUTING_DISCARDS: {
            SET_UNSIGNED_BIND(binding, LOWER_HALF(ip_stats->ip4.out_routing_discards));
            break;
        }

        case IP6_IP_FORWARDING: {
            SET_INTEGER_BIND(binding, LOWER_HALF(ip_stats->ip6.forwarding));
            break;
        }

        case IP6_IP_DEFAULT_HOP_LIMIT: {
            SET_INTEGER_BIND(binding, LOWER_HALF(ip_stats->ip6.default_ttl));
            break;
        }

        case IP4_INTERFACE_TABLE_LAST_CHANGE: {
            SET_TIME_TICKS_BIND(binding, 0);
            break;
        }

        case IP6_INTERFACE_TABLE_LAST_CHANGE: {
            uint32_t val = 0;
            IfaceEntry *cur = get_iface_list();
            while (cur != NULL) {
                if (cur->ip6_stats.updated > val) {
                    val = cur->ip6_stats.updated;
                }
                cur = cur->next;
            }
            SET_TIME_TICKS_BIND(binding, val ? 100 * rebase_duration(val) : 0);
            break;
        }

        case IP_ADDRESS_SPIN_LOCK:
        case IP6_ROUTER_ADVERT_SPIN_LOCK: {
            SET_INTEGER_BIND(binding, 0);
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
    switch (id) {
        case IP_ADDR_TABLE: {
            return get_ip_addr_table(column, row, row_len, binding, next_row);
        }

        case IP_NET_TO_MEDIA_TABLE: {
            return get_ip_to_media_table(column, row, row_len, binding, next_row);
        }

        case IP4_INTERFACE_TABLE: {
            return get_ip4_iface_table(column, row, row_len, binding, next_row);
        }

        case IP6_INTERFACE_TABLE: {
            return get_ip6_iface_table(column, row, row_len, binding, next_row);
        }

        case IP_ADDRESS_PREFIX_TABLE: {
            return get_ip_prefix_table(column, row, row_len, binding, next_row);
        }

        case IP_ADDRESS_TABLE: {
            return get_ip_address_table(column, row, row_len, binding, next_row);
        }

        case IP_NET_TO_PHYSICAL_TABLE: {
            return get_ip_to_phy_table(column, row, row_len, binding, next_row);
        }

        case IP6_SCOPE_ZONE_INDEX_TABLE: {
            return get_scope_table(column, row, row_len, binding, next_row);
        }

        case IP_DEFAULT_ROUTER_TABLE: {
            return get_default_route_table(column, row, row_len, binding, next_row);
        }

        case IP6_ROUTER_ADVERT_TABLE: {
            /* TODO parse radvd config file */
            EMPTY_TABLE(next_row, binding);
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
    this->sub_modules->finish_module(this->sub_modules);
    finish_single_level_module(this);
}

MibModule *init_ip_module(void)
{
    MibModule *traffic_stats = init_ip_traffic_stats_module();
    if (traffic_stats == NULL) {
        return NULL;
    }

    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, IP_FORWARDING,
            IP6_ROUTER_ADVERT_TABLE - IP_FORWARDING + 1,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, IP_AD_ENT_REASM_MAX_SIZE,
            LEAF_UNUSED, IP_NET_TO_MEDIA_TYPE, LEAF_SCALAR, LEAF_UNUSED,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR, IP4_INTERFACE_RETRANSMIT_TIME,
            LEAF_SCALAR, IP6_INTERFACE_FORWARDING, LEAF_SUBTREE,
            IP_ADDRESS_PREFIX_ADV_VALID_LIFETIME, LEAF_SCALAR,
            IP_ADDRESS_STORAGE_TYPE, IP_NET_TO_PHYSICAL_ROW_STATUS,
            IP6_SCOPE_ZONE_INDEX_D, IP_DEFAULT_ROUTER_PREFERENCE,
            LEAF_SCALAR, IP6_ROUTER_ADVERT_ROW_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_IP);
    SET_OR_ENTRY(module, &ip_stats_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    SET_SUBMODULE(module, traffic_stats);
    return &module->public;
}
