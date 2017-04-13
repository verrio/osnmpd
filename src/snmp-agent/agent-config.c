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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <pwd.h>
#include <grp.h>
#include <libconfig.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include "config.h"
#include "snmp-agent/agent-config.h"
#include "snmp-core/snmp-crypto.h"
#include "snmp-core/utils.h"

#ifdef SERIAL_NUMBER_SUPPORT
#define SERIAL_FETCH_COMMAND "/sbin/fw_printenv -n hardware.serial"
#define SERIAL_RESPONSE_FORMAT "010542503701%*6s%24s\n"
#endif

#define KEY_SEPARATOR "."
#define KEY_AGENT "agent"
#define KEY_IFACES	"interfaces"
#define KEY_PORT	"port"
#define KEY_UID		"uid"
#define KEY_GID		"gid"
#define KEY_ENGINE_ID	"engine-id"
#define KEY_CACHE_DIR	"cache-dir"
#define KEY_TRAP "trap"
#define KEY_TRAP_ENABLED	"enabled"
#define KEY_TRAP_CONFIRMED	"confirmed"
#define KEY_TRAP_USER	"user"
#define KEY_TRAP_DESTINATION	"destination"
#define KEY_TRAP_PORT	"port"
#define KEY_TRAP_RETRIES	"retries"
#define KEY_TRAP_TIMEOUT	"timeout"
#define KEY_USERS "users"
#define KEY_USER_SLOT "slot"
#define KEY_USER_ENABLED "enabled"
#define KEY_USER_NAME "name"
#define KEY_USER_AUTH_PASSWORD "auth-password"
#define KEY_USER_PRIV_PASSWORD "priv-password"
#define KEY_USER_SECURITY_MODEL "security-model"
#define KEY_USER_SECURITY_LEVEL "security-level"

#define DEFAULT_PORT 161
#define DEFAULT_TRAP_PORT 162
#define DEFAULT_UID 0
#define DEFAULT_GID 0
#define DEFAULT_ENGINE_ID	"AGENT"

#define ENGINE_ID_MAX_LEN 0x20
#define USER_NAME_MAX_LEN 0x40
#define USER_PASSWORD_MIN_LEN 0x8
#define USER_PASSWORD_MAX_LEN 0x40

static const char *USERS[] = { "PUBLIC", "READ_ONLY", "READ_WRITE", "ADMIN" };
static const char *SECURITY_MODELS[] = { "COMMUNITY", "USM", "TSM", "SSH" };
static const char *SECURITY_LEVELS[] = { "noauthnopriv", "authnopriv", "authpriv" };
static const char *DEFAULT_USER_NAMES[] = { "public", "readonly", "readwrite", "admin" };
static const char *TMP_EXTENSION = ".tmp";

/* runtime configuration */
static char *cache_dir = CACHE_DIR;
static char *config_file = CONF_DIR "/snmpd.conf";
static char **interfaces = NULL;
static TrapConfiguration trap_configuration;
static UserConfiguration user_configuration[NUMBER_OF_USER_SLOTS];
static int user_password_overruled[NUMBER_OF_USER_SLOTS];
static uint8_t engine_id[ENGINE_ID_MAX_LEN];
static size_t engine_id_len;
static uint16_t port = DEFAULT_PORT;
static unsigned int uid = DEFAULT_UID;
static unsigned int gid = DEFAULT_GID;

static SnmpUserSlot get_user_from_string(char const *user_name)
{
    if (user_name == NULL) {
        return -1;
    }

    for (int i = 0; i < NUMBER_OF_USER_SLOTS; i++) {
        if (strcasecmp(user_name, USERS[i]) == 0) {
            return i;
        }
    }

    return -1;
}

static char const *get_string_from_user(SnmpUserSlot slot)
{
    if (slot == -1) {
        return NULL;
    }

    return USERS[slot];
}

static SnmpSecurityModel get_security_model_from_string(char const *security_model)
{
    if (security_model == NULL) {
        return -1;
    }

    for (int i = 0; i < NUMBER_OF_SEC_MODELS; i++) {
        if (strcasecmp(security_model, SECURITY_MODELS[i]) == 0) {
            return i;
        }
    }

    return -1;
}

static char const *get_string_from_security_model(SnmpSecurityModel security_model)
{
    if (security_model == -1) {
        return NULL;
    }

    return SECURITY_MODELS[security_model];
}

static SnmpSecurityLevel get_security_level_from_string(char const *security_level)
{
    if (security_level == NULL) {
        return -1;
    }

    for (int i = 0; i < NUMBER_OF_SEC_LEVELS; i++) {
        if (strcasecmp(security_level, SECURITY_LEVELS[i]) == 0) {
            return i;
        }
    }

    return -1;
}

static char const *get_string_from_security_level(SnmpSecurityLevel security_level)
{
    if (security_level == -1) {
        return NULL;
    }

    return SECURITY_LEVELS[security_level];
}

static int load_passwords(void)
{
#ifdef WITH_SMARTCARD_SUPPORT
    ENGINE *e = get_smartcard_engine();
    if (e == NULL) {
        syslog(LOG_ERR, "missing smartcard engine : SNMP passwords not available");
        return -1;
    }

    syslog(LOG_DEBUG, "loading SNMP passwords from smartcard");

    /*
     * smartcard contains record with passwords:
     * MAN_PRIV, MAN_AUTH, RW_PRIV, RW_AUTH, RO_PRIV, RO_AUTH
     */
    uint8_t buffer[6 * USER_PASSWORD_MAX_LEN];
    if (!ENGINE_ctrl_cmd(e, "GET_SNMP_PASSWORDS", sizeof(buffer), buffer, NULL, 0)) {
        syslog(LOG_ERR, "failed to load SNMP passwords from smartcard");
        return -1;
    }

    user_configuration[USER_ADMIN].priv_password =
    strndup(buffer, USER_PASSWORD_MAX_LEN);
    user_configuration[USER_ADMIN].auth_password =
    strndup(&buffer[USER_PASSWORD_MAX_LEN], USER_PASSWORD_MAX_LEN);
    user_configuration[USER_READ_WRITE].priv_password =
    strndup(&buffer[2 * USER_PASSWORD_MAX_LEN], USER_PASSWORD_MAX_LEN);
    user_configuration[USER_READ_WRITE].auth_password =
    strndup(&buffer[3 * USER_PASSWORD_MAX_LEN], USER_PASSWORD_MAX_LEN);
    user_configuration[USER_READ_ONLY].priv_password =
    strndup(&buffer[4 * USER_PASSWORD_MAX_LEN], USER_PASSWORD_MAX_LEN);
    user_configuration[USER_READ_ONLY].auth_password =
    strndup(&buffer[5 * USER_PASSWORD_MAX_LEN], USER_PASSWORD_MAX_LEN);
#endif

    return 0;
}

static void set_default_engine_id(void)
{
    engine_id[0] = (ENTERPRISE_NUMBER  >> 24) & 0xff;
    engine_id[1] = (ENTERPRISE_NUMBER  >> 16) & 0xff;
    engine_id[2] = (ENTERPRISE_NUMBER  >> 8) & 0xff;
    engine_id[3] = ENTERPRISE_NUMBER & 0xff;
#ifdef SERIAL_NUMBER_SUPPORT
    engine_id[4] = 0x05;

    FILE *command = popen(SERIAL_FETCH_COMMAND, "r");
    if (command == NULL) {
        syslog(LOG_ERR, "failed to fetch serial number: %s", strerror(errno));
        goto err;
    }

    uint8_t buf[256];
    if (fgets(buf, sizeof(buf), command) == NULL) {
        syslog(LOG_ERR, "failed to fetch serial number: response empty");
        goto err;
    }
    pclose(command);

    if (sscanf(buf, SERIAL_RESPONSE_FORMAT, &engine_id[5]) != 1) {
        syslog(LOG_ERR, "unexpected serial number format : %s", buf);
        goto err;
    }

    engine_id_len = 5 + strnlen(&engine_id[5], 24);
    return;

    err: if (command != NULL)
        pclose(command);
    memset(&engine_id[5], 0, 8);
    engine_id_len = 13;
#else
    engine_id[0] |= 0x80;
    engine_id[4] = 0x03;
    engine_id_len = 11;

    int mac_found = 0;
    struct ifaddrs *if_addr;
    if (getifaddrs(&if_addr)) {
        syslog(LOG_ERR, "failed to determine engine id : %s", strerror(errno));
        return;
    }

    int sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == -1) {
        goto err;
    }

    for (struct ifaddrs *if_addr_ptr = if_addr; if_addr_ptr;
            if_addr_ptr = if_addr_ptr->ifa_next) {
        struct ifreq ifr;
        strcpy(ifr.ifr_name, if_addr_ptr->ifa_name);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
            continue;
        }

        memcpy(&engine_id[5], ifr.ifr_hwaddr.sa_data, 6);
        uint8_t zero_cmp[] = {0,0,0,0,0,0};
        if (memcmp(&engine_id[5], zero_cmp, 6)) {
            mac_found = 1;
            break;
        }
    }

    close(sock);
err:
    freeifaddrs(if_addr);
    if (!mac_found) {
        syslog(LOG_WARNING, "no valid MAC found");
    }
#endif
}

static void set_default_trap_config(void)
{
    trap_configuration.enabled = 0;
    trap_configuration.confirmed = 0;
    trap_configuration.user = READ_ONLY;
    trap_configuration.destination = NULL;
    trap_configuration.port = DEFAULT_TRAP_PORT;
    trap_configuration.retries = 3;
    trap_configuration.timeout = 10;
}

static void set_default_user_config(SnmpUserSlot user)
{
    user_configuration[user].user = user;
    user_configuration[user].enabled = 0;
    user_configuration[user].name = (char *) DEFAULT_USER_NAMES[user];
    user_configuration[user].auth_password = NULL;
    user_configuration[user].priv_password = NULL;
    user_configuration[user].security_level =
        user == USER_PUBLIC ? NO_AUTH_NO_PRIV : AUTH_PRIV;
    user_configuration[user].security_model = USM;
    user_password_overruled[user] = 0;
}

void set_config_file(char *path)
{
    config_file = path;
}

int load_configuration(void)
{
    set_default_user_config(USER_PUBLIC);
    set_default_user_config(USER_READ_ONLY);
    set_default_user_config(USER_READ_WRITE);
    set_default_user_config(USER_ADMIN);

    int ret_val = 0;
    config_t agent_cfg;

    config_init(&agent_cfg);

    if (access(config_file, F_OK) == -1) {
        syslog(LOG_WARNING,
                "configuration missing or not accessible;  using defaults");
        ret_val = -2;
        goto finish;
    }

    if (!config_read_file(&agent_cfg, config_file)) {
        syslog(LOG_ERR, "failed to parse configuration %s:%d - %s",
                config_error_file(&agent_cfg), config_error_line(&agent_cfg),
                config_error_text(&agent_cfg));
        set_default_engine_id();
        set_default_trap_config();
        ret_val = -1;
        goto finish;
    }

    if (load_passwords() == -1) {
        syslog(LOG_ERR, "failed to load user passwords");
        ret_val = -1;
    }

    const char *str;

    /* fetch uid */
    if (config_lookup_string(&agent_cfg,
    KEY_AGENT KEY_SEPARATOR KEY_UID, &str) == CONFIG_TRUE) {
        struct passwd *user = getpwnam(str);
        if (user == NULL) {
            syslog(LOG_ERR, "failed to find uid for user %s", str);
            uid = DEFAULT_UID;
            ret_val = -1;
        } else {
            uid = user->pw_uid;
        }
    } else {
        config_lookup_int(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_UID, (int *) &uid);
    }

    /* fetch gid */
    if (config_lookup_string(&agent_cfg,
    KEY_AGENT KEY_SEPARATOR KEY_GID, &str) == CONFIG_TRUE) {
        struct group *grp = getgrnam(str);
        if (grp == NULL) {
            syslog(LOG_ERR, "failed to find gid for group %s", str);
            gid = DEFAULT_GID;
            ret_val = -1;
        } else {
            gid = grp->gr_gid;
        }
    } else {
        config_lookup_int(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_GID, (int *) &gid);
    }

    /* fetch port config */
    int port_override;
    if (config_lookup_int(&agent_cfg,
    KEY_AGENT KEY_SEPARATOR KEY_PORT, &port_override) == CONFIG_TRUE) {
        port = (uint16_t) port_override;
    }

    /* fetch interfaces */
    config_setting_t *ifaces_config = config_lookup(&agent_cfg,
            KEY_AGENT KEY_SEPARATOR KEY_IFACES);
    if (ifaces_config != NULL) {
        size_t count = config_setting_length(ifaces_config);
        interfaces = malloc(sizeof(char *) * (count + 1));
        if (interfaces == NULL) {
            ret_val = -1;
        } else {
            interfaces[count] = NULL;
            for (int i = 0; i < count; i++) {
                char const *iface = config_setting_get_string_elem(ifaces_config, i);
                if (iface == NULL) {
                    syslog(LOG_ERR, "failed to parse interfaces");
                    continue;
                }
                interfaces[i] = strdup(iface);
            }
        }
    }

    /* fetch cache dir */
    if (config_lookup_string(&agent_cfg,
        KEY_AGENT KEY_SEPARATOR KEY_CACHE_DIR, &str) == CONFIG_TRUE) {
        struct stat cache_stat;
        cache_dir = strdup(str);
        if (cache_dir == NULL || stat(cache_dir, &cache_stat) != 0
            || !S_ISDIR(cache_stat.st_mode)) {
            ret_val = -1;
            syslog(LOG_ERR, "failed to access cache directory");
        }
    } else {
        syslog(LOG_DEBUG, "using default cache directory %s.", cache_dir);
    }

    /* fetch engine ID */
    if (config_lookup_string(&agent_cfg,
        KEY_AGENT KEY_SEPARATOR KEY_ENGINE_ID, &str) == CONFIG_TRUE) {
        engine_id_len = from_hex(str, engine_id, sizeof(engine_id));
        if (engine_id_len == -1) {
            syslog(LOG_ERR, "failed to parse engine id %s", str);
            ret_val = -1;
            set_default_engine_id();
        }
    } else {
        set_default_engine_id();
    }

    /* fetch trap configuration */
    config_lookup_bool(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_TRAP
    KEY_SEPARATOR KEY_TRAP_ENABLED, &trap_configuration.enabled);
    config_lookup_bool(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_TRAP
    KEY_SEPARATOR KEY_TRAP_CONFIRMED, &trap_configuration.confirmed);
    if (config_lookup_int(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_TRAP
    KEY_SEPARATOR KEY_TRAP_PORT, &port_override) == CONFIG_TRUE) {
        trap_configuration.port = (uint16_t) port_override;
    }
    config_lookup_int(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_TRAP
    KEY_SEPARATOR KEY_TRAP_RETRIES, (int *) &trap_configuration.retries);
    config_lookup_int(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_TRAP
    KEY_SEPARATOR KEY_TRAP_TIMEOUT, (int *) &trap_configuration.timeout);
    if (config_lookup_string(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_TRAP
    KEY_SEPARATOR KEY_TRAP_DESTINATION, &str) == CONFIG_TRUE) {
        trap_configuration.destination = strdup(str);
    } else {
        trap_configuration.destination = NULL;
    }
    if (config_lookup_string(&agent_cfg, KEY_AGENT KEY_SEPARATOR KEY_TRAP
    KEY_SEPARATOR KEY_TRAP_USER, &str) == CONFIG_TRUE) {
        trap_configuration.user = get_user_from_string(str);
        if (trap_configuration.user == -1) {
            syslog(LOG_ERR, "no user for profile %s", str);
            ret_val = -1;
            trap_configuration.user = READ_ONLY;
        }
    } else {
        trap_configuration.user = READ_ONLY;
    }

    /* fetch user configuration */
    config_setting_t *user_config = config_lookup(&agent_cfg,
            KEY_AGENT KEY_SEPARATOR KEY_USERS);
    if (user_config != NULL) {
        int count = config_setting_length(user_config);

        for (int i = 0; i < count; i++) {
            config_setting_t *user = config_setting_get_elem(user_config, i);
            SnmpUserSlot slot;

            if (config_setting_lookup_string(user, KEY_USER_SLOT,
                    &str) == CONFIG_FALSE) {
                syslog(LOG_ERR, "user config with missing slot");
                ret_val = -1;
                continue;
            } else if ((slot = get_user_from_string(str)) == -1) {
                syslog(LOG_ERR, "no user for slot %s", str);
                ret_val = -1;
                continue;
            }

            /* enable/disable user */
            config_setting_lookup_bool(user,
            KEY_USER_ENABLED, &user_configuration[slot].enabled);

            /* override user name */
            if (config_setting_lookup_string(user,
            KEY_USER_NAME, &str) == CONFIG_TRUE) {
                if (strlen(str) > USER_NAME_MAX_LEN) {
                    syslog(LOG_ERR, "user name too long: %s", str);
                    ret_val = -1;
                } else {
                    user_configuration[slot].name = strdup(str);
                    if (user_configuration[slot].name == NULL) {
                        user_configuration[slot].name = (char *) DEFAULT_USER_NAMES[slot];
                        ret_val = -1;
                    }
                }
            }

            /* set user password override */
            user_password_overruled[slot] = 0;
            if (config_setting_lookup_string(user,
            KEY_USER_AUTH_PASSWORD, &str) == CONFIG_TRUE) {
                if (strlen(str) > USER_PASSWORD_MAX_LEN) {
                    syslog(LOG_ERR, "user authentication password too long : %s", str);
                    ret_val = -1;
                } else {
                    user_configuration[slot].auth_password = strdup(str);
                    user_password_overruled[slot] = 1;
                }
            }
            if (config_setting_lookup_string(user,
            KEY_USER_PRIV_PASSWORD, &str) == CONFIG_TRUE) {
                if (strlen(str) > USER_PASSWORD_MAX_LEN) {
                    syslog(LOG_ERR, "user privacy password too long : %s", str);
                    ret_val = -1;
                } else {
                    user_configuration[slot].priv_password = strdup(str);
                    user_password_overruled[slot] = 1;
                }
            }

            /* set user security model */
            if (config_setting_lookup_string(user,
            KEY_USER_SECURITY_MODEL, &str) == CONFIG_TRUE) {
                user_configuration[slot].security_model =
                        get_security_model_from_string(str);
                if (user_configuration[slot].security_model == -1) {
                    syslog(LOG_ERR, "unsupported security model %s", str);
                    ret_val = -1;
                    user_configuration[slot].security_model = USM;
                }
            }

            /* set user security level */
            if (config_setting_lookup_string(user,
            KEY_USER_SECURITY_LEVEL, &str) == CONFIG_TRUE) {
                user_configuration[slot].security_level =
                        get_security_level_from_string(str);
                if (user_configuration[slot].security_level == -1) {
                    syslog(LOG_ERR, "unsupported security level %s", str);
                    ret_val = -1;
                    user_configuration[slot].security_level = AUTH_PRIV;
                }
            }
        }
    }

    finish: config_destroy(&agent_cfg);
    return ret_val;
}

int write_configuration(void)
{
    char *tmp_file = NULL;
    int ret_val = 0;
    config_t cfg;
    config_setting_t *setting;

    config_init(&cfg);

    /* read existing configuration file */
    if (!config_read_file(&cfg, config_file)) {
        syslog(LOG_ERR, "failed to read existing config file : %s:%d - %s",
                config_error_file(&cfg), config_error_line(&cfg),
                config_error_text(&cfg));
    }

    config_setting_t *root = config_root_setting(&cfg);

    config_setting_t *agent = config_setting_get_member(root, KEY_AGENT);
    if (!agent) {
        agent = config_setting_add(root, KEY_AGENT, CONFIG_TYPE_GROUP);
    }

    /* set port config */
    config_setting_remove(agent, KEY_PORT);
    setting = config_setting_add(agent, KEY_PORT, CONFIG_TYPE_INT);
    config_setting_set_int(setting, 0x00ffff & port);

    /* set engine ID */
    char engine_buf[(ENGINE_ID_MAX_LEN << 1) + 3];
    if (to_hex(engine_id, engine_id_len, engine_buf,
            (ENGINE_ID_MAX_LEN << 1) + 3) != -1) {
        config_setting_remove(agent, KEY_ENGINE_ID);
        setting = config_setting_add(agent, KEY_ENGINE_ID, CONFIG_TYPE_STRING);
        config_setting_set_string(setting, engine_buf);
    } else {
        syslog(LOG_ERR, "failed to update engine id");
    }

    /* set interfaces */
    config_setting_remove(agent, KEY_IFACES);
    config_setting_t *ifaces = config_setting_add(agent, KEY_IFACES,
            CONFIG_TYPE_ARRAY);
    if (interfaces != NULL) {
        for (int i = 0; interfaces[i] != NULL; i++) {
            setting = config_setting_add(ifaces, KEY_IFACES, CONFIG_TYPE_STRING);
            config_setting_set_string(setting, interfaces[i]);
        }
    }

    /* set trap configuration */
    config_setting_remove(agent, KEY_TRAP);
    config_setting_t *trap = config_setting_add(agent, KEY_TRAP,
            CONFIG_TYPE_GROUP);
    setting = config_setting_add(trap, KEY_TRAP_ENABLED, CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, trap_configuration.enabled);
    setting = config_setting_add(trap, KEY_TRAP_CONFIRMED, CONFIG_TYPE_BOOL);
    config_setting_set_bool(setting, trap_configuration.confirmed);
    char const *user_name = get_string_from_user(trap_configuration.user);
    if (user_name != NULL) {
        setting = config_setting_add(trap, KEY_TRAP_USER, CONFIG_TYPE_STRING);
        config_setting_set_string(setting, user_name);
    }
    if (trap_configuration.destination != NULL) {
        setting = config_setting_add(trap, KEY_TRAP_DESTINATION, CONFIG_TYPE_STRING);
        config_setting_set_string(setting, trap_configuration.destination);
    }
    setting = config_setting_add(trap, KEY_TRAP_PORT, CONFIG_TYPE_INT);
    config_setting_set_int(setting, 0x00ffff & trap_configuration.port);
    setting = config_setting_add(trap, KEY_TRAP_RETRIES, CONFIG_TYPE_INT);
    config_setting_set_int(setting, trap_configuration.retries);
    setting = config_setting_add(trap, KEY_TRAP_TIMEOUT, CONFIG_TYPE_INT);
    config_setting_set_int(setting, trap_configuration.timeout);

    /* set user configuration */
    config_setting_remove(agent, KEY_USERS);
    config_setting_t *users = config_setting_add(agent, KEY_USERS,
            CONFIG_TYPE_LIST);
    for (int i = 0; i < NUMBER_OF_USER_SLOTS; i++) {
        config_setting_t *user = config_setting_add(users, NULL,
                CONFIG_TYPE_GROUP);

        /* set user slot */
        setting = config_setting_add(user, KEY_USER_SLOT, CONFIG_TYPE_STRING);
        config_setting_set_string(setting, get_string_from_user(i));

        /* set user enabled */
        setting = config_setting_add(user, KEY_USER_ENABLED, CONFIG_TYPE_BOOL);
        config_setting_set_bool(setting, user_configuration[i].enabled);

        /* set user name */
        if (user_configuration[i].name != NULL) {
            setting = config_setting_add(user, KEY_USER_NAME, CONFIG_TYPE_STRING);
            config_setting_set_string(setting, user_configuration[i].name);
        }

        /* set user security model */
        char const *sec_model = get_string_from_security_model(
                user_configuration[i].security_model);
        if (sec_model != NULL) {
            setting = config_setting_add(user, KEY_USER_SECURITY_MODEL,
                CONFIG_TYPE_STRING);
            config_setting_set_string(setting, sec_model);
        }

        /* set user security level */
        char const *sec_level = get_string_from_security_level(
                user_configuration[i].security_level);
        if (sec_level != NULL) {
            setting = config_setting_add(user, KEY_USER_SECURITY_LEVEL,
                CONFIG_TYPE_STRING);
            config_setting_set_string(setting, sec_level);
        }

        if (user_password_overruled[i]) {
            /* set authentication password */
            if (user_configuration[i].auth_password != NULL) {
                setting = config_setting_add(user, KEY_USER_AUTH_PASSWORD,
                    CONFIG_TYPE_STRING);
                config_setting_set_string(setting, user_configuration[i].auth_password);
            }

            /* set privacy password */
            if (user_configuration[i].priv_password != NULL) {
                setting = config_setting_add(user, KEY_USER_PRIV_PASSWORD,
                    CONFIG_TYPE_STRING);
                config_setting_set_string(setting, user_configuration[i].priv_password);
            }
        }
    }

    tmp_file = strconcat(config_file, TMP_EXTENSION);
    if (tmp_file == NULL) {
        syslog(LOG_ERR, "failed to write new configuration file : out of memory");
        ret_val = -1;
        goto finish;
    }
    if (!config_write_file(&cfg, tmp_file)) {
        syslog(LOG_ERR, "failed to update configuration file %s", config_file);
        ret_val = -1;
        goto finish;
    }
    if (rename(tmp_file, config_file) == -1) {
        syslog(LOG_ERR, "failed to move new configuration file : %s", strerror(errno));
        ret_val = -1;
        goto finish;
    }

    syslog(LOG_INFO, "successfully updated configuration file %s", config_file);
    finish: if (tmp_file != NULL) {
        free(tmp_file);
    }
    config_destroy(&cfg);
    return ret_val;
}

char *get_cache_dir(void)
{
    return cache_dir;
}

int get_agent_uid(void)
{
    return uid;
}

int get_agent_gid(void)
{
    return gid;
}

int get_agent_port(void)
{
    return port;
}

int set_agent_port(int new_port)
{
    if (new_port < 0 || new_port == 80 || new_port == 443 || new_port == 4059) {
        return -1;
    }

    port = new_port;
    return 0;
}

char **get_agent_interfaces(void)
{
    return interfaces;
}

int set_agent_interfaces(char *ifaces[])
{
    if (interfaces != NULL) {
        for (int i = 0; interfaces[i] != NULL; i++) {
            free(interfaces[i]);
        }
        free(interfaces);
    }

    int count = 0;
    while (ifaces[count] != NULL) {
        count++;
    }

    interfaces = malloc(sizeof(uint8_t *) * (count + 1));
    if (interfaces == NULL) {
        return -1;
    }
    interfaces[count] = NULL;
    for (int i = 0; i < count; i++) {
        interfaces[i] = strdup(ifaces[i]);
        if (interfaces[i] == NULL) {
            return -1;
        }
    }

    return 0;
}

TrapConfiguration *get_trap_configuration(void)
{
    return &trap_configuration;
}

int set_trap_configuration(TrapConfiguration *configuration)
{
    trap_configuration.enabled = configuration->enabled;
    trap_configuration.confirmed = configuration->confirmed;
    trap_configuration.user = configuration->user;
    trap_configuration.port = configuration->port;
    if (trap_configuration.destination != NULL) {
        free(trap_configuration.destination);
    }
    if (configuration->destination != NULL) {
        trap_configuration.destination = strdup(configuration->destination);
        if (trap_configuration.destination == NULL) {
            return -1;
        }
    } else {
        configuration->destination = NULL;
    }

    return 0;
}

UserConfiguration *get_user_configuration(SnmpUserSlot user)
{
    return &user_configuration[user];
}

int set_user_configuration(UserConfiguration *configuration)
{
    if (configuration->user == -1) {
        return -1;
    }

    SnmpUserSlot slot = configuration->user;
    user_configuration[slot].enabled = configuration->enabled;
    user_configuration[slot].security_level = configuration->security_level;
    user_configuration[slot].security_model = configuration->security_model;

    if (user_configuration[slot].name != (char *) DEFAULT_USER_NAMES[slot]) {
        free(user_configuration[slot].name);
    }
    if (configuration->name == NULL) {
        user_configuration[slot].name = (char *) DEFAULT_USER_NAMES[slot];
    } else {
        user_configuration[slot].name = strdup(configuration->name);
        if (user_configuration[slot].name == NULL) {
            user_configuration[slot].name = (char *) DEFAULT_USER_NAMES[slot];
            return -1;
        }
    }

    return 0;
}

int set_user_auth_password(SnmpUserSlot user, char *password)
{
    if (user == USER_PUBLIC|| password == NULL
        || strlen(password) > USER_PASSWORD_MAX_LEN
        || strlen(password) < USER_PASSWORD_MIN_LEN) {
        return -1;
    }

    if (user_configuration[user].auth_password != NULL) {
        free(user_configuration[user].auth_password);
    }

    user_configuration[user].auth_password = strdup(password);
    if (user_configuration[user].auth_password == NULL) {
        return -1;
    }

#ifdef WITH_SMARTCARD_SUPPORT
    ENGINE *e = get_smartcard_engine();
    if (e == NULL) {
        syslog(LOG_ERR, "missing smartcard engine : SNMP password cannot be updated");
        return -1;
    }

    syslog(LOG_DEBUG, "updating SNMP authentication password for user %u", user);

    uint8_t buffer[USER_PASSWORD_MAX_LEN];
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, password, strlen(password));
    int slot = ((user == USER_ADMIN ? 0 : (user == USER_READ_WRITE ? 1 : 2)) << 1) + 1;

    if (!ENGINE_ctrl_cmd(e, "SET_SNMP_PASSWORD", slot, buffer, NULL, 0)) {
        syslog(LOG_ERR, "failed to update SNMP authentication password");
        return -1;
    }
#endif

    return 0;
}

int set_user_priv_password(SnmpUserSlot user, char *password)
{
    if (user == USER_PUBLIC|| password == NULL
        || strlen(password) > USER_PASSWORD_MAX_LEN
        || strlen(password) < USER_PASSWORD_MIN_LEN) {
        return -1;
    }

    if (user_configuration[user].priv_password != NULL) {
        free(user_configuration[user].priv_password);
    }

    user_configuration[user].priv_password = strdup(password);
    if (user_configuration[user].priv_password == NULL) {
        return -1;
    }

#ifdef WITH_SMARTCARD_SUPPORT
    ENGINE *e = get_smartcard_engine();
    if (e == NULL) {
        syslog(LOG_ERR, "missing smartcard engine : SNMP password cannot be updated");
        return -1;
    }

    syslog(LOG_DEBUG, "updating SNMP privacy password for user %u", user);

    uint8_t buffer[USER_PASSWORD_MAX_LEN];
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, password, strlen(password));
    int slot = ((user == USER_ADMIN ? 0 : (user == USER_READ_WRITE ? 1 : 2)) << 1);

    if (!ENGINE_ctrl_cmd(e, "SET_SNMP_PASSWORD", slot, buffer, NULL, 0)) {
        syslog(LOG_ERR, "failed to update SNMP privacy password");
        return -1;
    }
#endif

    return 0;
}

size_t get_engine_id(uint8_t **engine_id_buf)
{
    *engine_id_buf = engine_id;
    return engine_id_len;
}

int set_engine_id(const uint8_t *new_engine_id, const size_t new_engine_id_len)
{
    if (new_engine_id_len > ENGINE_ID_MAX_LEN) {
        fprintf(stderr, "given engine ID of length %zu exceeds max length",
                new_engine_id_len);
        return -1;
    }

    memcpy(engine_id, new_engine_id, new_engine_id_len);
    engine_id_len = new_engine_id_len;
    return 0;
}
