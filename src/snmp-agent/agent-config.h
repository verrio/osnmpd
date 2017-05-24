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

#ifndef SRC_AGENT_CONFIG_H_
#define SRC_AGENT_CONFIG_H_

#include "snmp-agent/snmpd.h"
#include "snmp-core/snmp-crypto.h"

typedef struct {
	int enabled;
	int confirmed;
	SnmpUserSlot user;
	char *destination;
	uint16_t port;
	uint32_t retries;
	uint32_t timeout;
} TrapConfiguration;

typedef struct {

    /* user profile */
	SnmpUserSlot user;

	/* user enabled */
	int enabled;

	/* user security name */
	char *name;

	/* privacy password or derived key */
	SnmpUSMSecret priv_secret;

	/* authentication password or derived key */
	SnmpUSMSecret auth_secret;

	/* security model enforced for this user */
	SnmpSecurityModel security_model;

	/* security level enforced for this user */
	SnmpSecurityLevel security_level;

} UserConfiguration;

/**
 * set_config_file - sets the configuration file to the given path.
 *
 * @param path IN - config file path (not duplicated)
 */
void set_config_file(char *path);

/**
 * load_configuration - initialize the agent configuration.
 *
 * @return 0 on success or -1 on any error
 */
__attribute__((visibility("default")))
int load_configuration(void);

/**
 * write_configuration - write the current agent configuration to disk.
 *
 * @return 0 on success or -1 on any error
 */
__attribute__((visibility("default")))
int write_configuration(void);

/**
 * get_cache_dir - returns the directory in which to store the agent's cache.
 *
 * @return cache directory.
 */
char *get_cache_dir(void);

/**
 * get_uid - returns the daemon UID.
 *
 * @return daemon user ID.
 */
int get_agent_uid(void);

/**
 * get_gid - returns the daemon GID.
 *
 * @return daemon user group.
 */
int get_agent_gid(void);

/**
 * get_port - returns the UDP port on which to bind.
 *
 * @return UDP port on which to bind.
 */
__attribute__((visibility("default")))
int get_agent_port(void);

/**
 * set_port - sets the UDP port on which to bind.
 *
 * @param port IN - new UDP port
 *
 * @return 0 on success or -1 on any error
 */
__attribute__((visibility("default")))
int set_agent_port(int port);

/**
 * get_interfaces - returns the list of interfaces on which to listen,
 * or NULL if no such list exists.
 *
 * @return interfaces on which to listen.
 */
char **get_agent_interfaces(void);

/**
 * set_interfaces - sets the interfaces on which to listen.
 *
 * @param ifaces IN - new list of interfaces
 *
 * @return 0 on success or -1 on any error
 */
int set_agent_interfaces(char *ifaces[]);

/**
 * get_trap_configuration - returns the trap configuration.
 *
 * @return pointer to trap configuration (internal, not freed by caller)
 */
__attribute__((visibility("default")))
TrapConfiguration *get_trap_configuration(void);

/**
 * set_trap_configuration - updates the trap configuration.
 *
 * @param configuration   IN - new trap configuration
 *
 * @return 0 on success or -1 on any error
 */
__attribute__((visibility("default")))
int set_trap_configuration(TrapConfiguration *configuration);

/**
 * get_user_configuration - returns the configuration for the given user profile.
 *
 * @param user IN - selected user
 *
 * @return pointer to user configuration (internal, not freed by caller)
 */
__attribute__((visibility("default")))
UserConfiguration *get_user_configuration(SnmpUserSlot user);

/**
 * set_user_configuration - updates the configuration for a given user profile.
 * password field is ignored.
 *
 * @param configuration   IN - new user configuration
 *
 * @return 0 on success or -1 on any error
 */
int set_user_configuration(UserConfiguration *configuration);

/**
 * set_user_priv_password - updates the privacy password for a given user.
 *
 * @param user       IN - selected user slot
 * @param password   IN - new privacy password
 *
 * @return 0 on success or -1 on any error
 */
int set_user_priv_password(SnmpUserSlot user, char *password);

/**
 * set_user_auth_password - updates the authentication password for a given user.
 *
 * @param user       IN - selected user slot
 * @param password   IN - new authentication password
 *
 * @return 0 on success or -1 on any error
 */
int set_user_auth_password(SnmpUserSlot user, char *password);

/**
 * set_user_priv_derived_key - updates the privacy key for a given user.
 *
 * @param user     IN - selected user slot
 * @param key      IN - new privacy key
 * @param key_len  IN - key length
 *
 * @return 0 on success or -1 on any error
 */
__attribute__((visibility("default")))
int set_user_priv_key(SnmpUserSlot user, const uint8_t *key, size_t key_len);

/**
 * set_user_auth_derived_key - updates the authentication key for a given user.
 *
 * @param user     IN - selected user slot
 * @param key      IN - new authentication key
 * @param key_len  IN - key length
 *
 * @return 0 on success or -1 on any error
 */
__attribute__((visibility("default")))
int set_user_auth_key(SnmpUserSlot user, const uint8_t *key, size_t key_len);

/**
 * get_engine_id - updates the engine ID to the given string.
 * internal pointer, should not be freed by caller.
 *
 * @param engine_id       OUT - pointer to start of engine id buffer
 *
 * @return length of engine ID
 */
__attribute__((visibility("default")))
size_t get_engine_id(uint8_t **engine_id);

/**
 * set_engine_id - updates the engine ID to the given string.
 *
 * @param engine_id       IN - pointer to start of engine id buffer
 * @param engine_id_len   IN - length of new engine id
 *
 * @return 0 on success or -1 on any error
 */
int set_engine_id(const uint8_t *engine_id, const size_t engine_id_len);

#endif /* SRC_AGENT_CONFIG_H_ */
