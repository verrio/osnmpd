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

#ifndef SRC_MIB_MODULE_MIB_MODULE_H_
#define SRC_MIB_MODULE_MIB_MODULE_H_

#include "snmp-core/snmp-types.h"

#define SET_PREFIX(module, ...) SET_OID(((MibModule *) module)->prefix, __VA_ARGS__)
#define SET_OR_ENTRY(module, entry) ((MibModule *) module)->or_entry = entry
#define SET_METHOD(module, type, method) ((type *) module)->method = _##method
#define DEF_METHOD(name, ret, super, type, ...) \
    static ret name(union {super *public; type *this;} \
    __attribute__((transparent_union)), ##__VA_ARGS__); \
    static typeof(name) *_##name = (typeof(name)*)name; \
    static ret name(type *this, ##__VA_ARGS__)

/* sysOR table entry */
typedef struct SysOREntry {

    /* authoritative identification of a capabilities statement */
    OID or_id;

    /* textual description of the module's capabilities */
    char *or_descr;

    /* next entry in list */
    struct SysOREntry *next;

} SysOREntry;

/* Collection of MIB entries grouped under a common OID prefix */
typedef struct MibModule {

    /* OID prefix and descriptor managed by this module */
    OID prefix;
    SysOREntry *or_entry;

    /* SNMP actions on subtree */
    SnmpErrorStatus (*get_var)(struct MibModule *mod, SnmpVariableBinding *binding);
    SnmpErrorStatus (*get_next_var)(struct MibModule *mod, SnmpVariableBinding *binding);
    SnmpErrorStatus (*set_var)(struct MibModule *mod,
        SnmpVariableBinding *binding, int dry_run);

    /* destroy the module */
    void (*finish_module)(struct MibModule *mod);

} MibModule;

typedef enum ApplicationOperStatus {
    NET_APP_UP = 1,
    NET_APP_DOWN = 2,
    NET_APP_HALTED = 3,
    NET_APP_CONGESTED = 4,
    NET_APP_RESTARTING = 5
} ApplicationOperStatus;

/* Network application registered on the SNMP agent */
typedef struct MibApplicationModule {

    /* application descriptors */
    char *(*get_name)(void);
    char *(*get_version)(void);
    char *(*get_description)(void);

    /* application state */
    ApplicationOperStatus (*get_oper_state)(void);

    /* timestamps (relative to system boot, in seconds) */
    uint32_t (*get_uptime)(void);
    uint32_t (*get_last_change)(void);
    uint32_t (*get_last_inbound)(void);
    uint32_t (*get_last_outbound)(void);

    /* counters */
    uint32_t (*get_inbound_assoc)(void);
    uint32_t (*get_acc_inbound_assoc)(void);
    uint32_t (*get_acc_failed_inbound_assoc)(void);
    uint32_t (*get_outbound_assoc)(void);
    uint32_t (*get_acc_outbound_assoc)(void);
    uint32_t (*get_acc_failed_outbound_assoc)(void);

    /* next entry in list */
    struct MibApplicationModule *next;

} MibApplicationModule;

#endif /* SRC_MIB_MODULE_MIB_MODULE_H_ */
