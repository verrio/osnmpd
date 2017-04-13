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

#ifndef SRC_SNMP_MIB_IP_IP_ADDRESS_CACHE_H_
#define SRC_SNMP_MIB_IP_IP_ADDRESS_CACHE_H_

#define ADDRESS_LENGTH(x) (((IpAddressEntry *) (x))->family == ADDRESS_IP4 ? 4 : 16)

enum IpAddressFamily {
    ADDRESS_UNKNOWN = 0,
    ADDRESS_IP4 = 1,
    ADDRESS_IP6 = 2
};

enum IpToPhysicalType {
    IP_TO_PHY_TYPE_OTHER = 1,
    IP_TO_PHY_TYPE_INVALID = 2,
    IP_TO_PHY_TYPE_DYNAMIC = 3,
    IP_TO_PHY_TYPE_STATIC = 4,
    IP_TO_PHY_TYPE_LOCAL = 5
};

enum IpToPhysicalState {
    IP_TO_PHY_STATE_REACHABLE = 1,
    IP_TO_PHY_STATE_STALE = 2,
    IP_TO_PHY_STATE_DELAY = 3,
    IP_TO_PHY_STATE_PROBE = 4,
    IP_TO_PHY_STATE_INVALID = 5,
    IP_TO_PHY_STATE_UNKNOWN = 6,
    IP_TO_PHY_STATE_INCOMPLETE = 7
};

enum IpAddressStatusTC {
    IP_ADDRESS_STATUS_PREFERRED = 1,
    IP_ADDRESS_STATUS_DEPRECATED = 2,
    IP_ADDRESS_STATUS_INVALID = 3,
    IP_ADDRESS_STATUS_INACCESSIBLE = 4,
    IP_ADDRESS_STATUS_UNKNOWN = 5,
    IP_ADDRESS_STATUS_TENTATIVE = 6,
    IP_ADDRESS_STATUS_DUPLICATE = 7,
    IP_ADDRESS_STATUS_OPTIMISTIC = 8
};

enum IpAddressOriginTC {
    IP_ADDRESS_ORIGIN_OTHER = 1,
    IP_ADDRESS_ORIGIN_MANUAL = 2,
    IP_ADDRESS_ORIGIN_DHCP = 3,
    IP_ADDRESS_ORIGIN_LINKLAYER = 4,
    IP_ADDRESS_ORIGIN_RANDOM = 5
};

enum IpAddressAddressingType {
    IP_ADDRESSING_TYPE_UNICAST = 1,
    IP_ADDRESSING_TYPE_ANYCAST = 2,
    IP_ADDRESSING_TYPE_BROADCAST = 3
};

typedef struct IpAddressEntry {
    enum IpAddressFamily family;
    uint8_t address[16];
    uint8_t address_type;
    uint8_t status;
    uint8_t origin;
    uint32_t iface;
    uint32_t prefix;
    uint32_t created;
    uint32_t last_changed;
    uint32_t valid;
    uint32_t preferred;
    struct IpAddressEntry *next;
} IpAddressEntry;

typedef struct IpToPhysicalAddressEntry {
    enum IpAddressFamily family;
    uint8_t address[16];
    uint8_t physical[64];
    size_t physical_len;
    uint32_t iface;
    uint32_t last_changed;
    enum IpToPhysicalType mapping;
    enum IpToPhysicalState state;
    struct IpToPhysicalAddressEntry *next;
} IpToPhysicalAddressEntry;

typedef struct IpDefaultRouteEntry {
    enum IpAddressFamily family;
    uint8_t address[16];
    uint32_t iface;
    uint32_t lifetime;
    int preference;
    struct IpDefaultRouteEntry *next;
} IpDefaultRouteEntry;

/**
 * @internal
 * get_address_list - returns the current IP address list
 *
 * @return ip address list
 */
IpAddressEntry *get_ip_address_list(void);

/**
 * @internal
 * get_ip_to_phy_address_list - returns the current
 * IP address to physical address mapping
 *
 * @return ip address to physical address list
 */
IpToPhysicalAddressEntry *get_ip_to_phy_address_list(void);

/**
 * @internal
 * get_ip_default_route_list - returns the list
 * of default gateway addresses
 *
 * @return ip default gateway addresses
 */
IpDefaultRouteEntry *get_ip_default_route_list(void);

#endif /* SRC_SNMP_MIB_IP_IP_ADDRESS_CACHE_H_ */
