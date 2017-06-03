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

#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/power/power-cache.h"

#define UPDATE_INTERVAL 8
#define SOCK_TIMEOUT 4

#define PATH_UPS_SOCK "/var/lib/nut"
#define PATH_BATTERY "/sys/class/power_supply/"
#define PATH_BATTERY_TECHNOLOGY "technology"
#define PATH_BATTERY_TYPE "type"
#define PATH_BATTERY_MANUFACTURER "manufacturer"
#define PATH_BATTERY_MODEL "model_name"
#define PATH_BATTERY_SERIAL "serial_number"
#define PATH_BATTERY_CYCLES "cycle_count"
#define PATH_BATTERY_VOLTAGE_NOW "voltage_now"
#define PATH_BATTERY_VOLTAGE_MIN "voltage_min_design"
#define PATH_BATTERY_CHARGE_NOW "charge_now"
#define PATH_BATTERY_CHARGE_FULL "charge_full"
#define PATH_BATTERY_CHARGE_DESIGN "charge_full_design"
#define PATH_BATTERY_CURRENT_NOW "current_now"
#define PATH_BATTERY_CURRENT_MAX "current_max"
#define PATH_BATTERY_STATUS "status"
#define PATH_BATTERY_TEMPERATURE "temp"

static int get_ups_sock(void);
static int parse_ups_buf(char *, UPSEntry *);
static void *fetch_ups_info(void);
static void scan_ups_string(char *, size_t, const char *);
static void scan_ups_decimal(uint32_t *, int, const char *);
static void *fetch_battery_list(void);
static void free_battery_list(void *);
static enum BatteryTechnology get_battery_technology(char *);
static enum BatteryType get_battery_type(char *);
static enum BatteryOperState get_battery_oper_status(char *);
static size_t fill_buffer(char *, char *, char *, size_t);
static int read_unsigned_number(char *, char *, uint32_t *);

static const char *ups_cmd_get = "DUMPALL\n";
static const char *ups_cmd_info = "SETINFO";
static const char *ups_cmd_done = "DUMPDONE";

enum UPSInfoType {
    UPS_INFO_STRING,
    UPS_INFO_DECIMAL,
    UPS_INFO_BOOL,
    UPS_INFO_STATUS,
    UPS_INFO_TEST_STATUS
};

typedef struct {
    char *key;
    enum UPSInfoType type;
    size_t offset;
    int multiplier;
} UPSInfo;

static const UPSInfo ups_info[] = {
    { "battery.charge", UPS_INFO_DECIMAL, offsetof(UPSEntry, charge_remaining), 1 },
    { "battery.current", UPS_INFO_DECIMAL, offsetof(UPSEntry, current), 10 },
    { "battery.runtime", UPS_INFO_DECIMAL, offsetof(UPSEntry, minutes_remaining), 1 },
    { "battery.runtime.low", UPS_INFO_BOOL, offsetof(UPSEntry, config_low_batt_time), 1 },
    { "battery.temperature", UPS_INFO_DECIMAL, offsetof(UPSEntry, temperature), 10 },
    { "battery.voltage", UPS_INFO_DECIMAL, offsetof(UPSEntry, voltage), 10 },
    { "debug.upsIdentAttachedDevices", UPS_INFO_STRING, offsetof(UPSEntry, attached_devices), 0 },
    { "debug.upsIdentName", UPS_INFO_STRING, offsetof(UPSEntry, ident), 0 },
    { "debug.upsInputLineBads", UPS_INFO_DECIMAL, offsetof(UPSEntry, num_line_bad), 1 },
    { "debug.upsSecondsOnBattery", UPS_INFO_DECIMAL, offsetof(UPSEntry, seconds_on_battery), 1 },
    { "debug.upsTestStartTime", UPS_INFO_DECIMAL, offsetof(UPSEntry, test_start_time), 1 },
    { "debug.upsTestElapsedTime", UPS_INFO_DECIMAL, offsetof(UPSEntry, test_elapsed_time), 1 },
    { "device.mfr", UPS_INFO_STRING, offsetof(UPSEntry, manufacturer), 0 },
    { "device.model", UPS_INFO_STRING, offsetof(UPSEntry, model), 0 },
    { "device.type", UPS_INFO_STRING, offsetof(UPSEntry, attached_devices), 0 },
    { "driver.name", UPS_INFO_STRING, offsetof(UPSEntry, ident), 0 },
    { "input.bypass.phases", UPS_INFO_DECIMAL, offsetof(UPSEntry, bypass_num_lines), 1 },
    { "input.bypass.frequency", UPS_INFO_DECIMAL, offsetof(UPSEntry, bypass_freq), 10 },
    { "input.bypass.voltage", UPS_INFO_DECIMAL, offsetof(UPSEntry, bypass_voltage), 1 },
    { "input.bypass.current", UPS_INFO_DECIMAL, offsetof(UPSEntry, bypass_current), 10 },
    { "input.bypass.realpower", UPS_INFO_DECIMAL, offsetof(UPSEntry, bypass_power), 1 },
    { "input.current", UPS_INFO_DECIMAL, offsetof(UPSEntry, input_current), 10 },
    { "input.phases", UPS_INFO_DECIMAL, offsetof(UPSEntry, num_lines), 1 },
    { "input.frequency", UPS_INFO_DECIMAL, offsetof(UPSEntry, input_freq), 1 },
    { "input.frequency.nominal", UPS_INFO_DECIMAL, offsetof(UPSEntry, config_input_freq), 10 },
    { "input.realpower", UPS_INFO_DECIMAL, offsetof(UPSEntry, input_power), 1 },
    { "input.transfer.low", UPS_INFO_DECIMAL, offsetof(UPSEntry, config_low_voltage_transfer), 1 },
    { "input.transfer.high", UPS_INFO_DECIMAL, offsetof(UPSEntry, config_high_voltage_transfer), 1 },
    { "input.voltage", UPS_INFO_DECIMAL, offsetof(UPSEntry, input_voltage), 1 },
    { "input.voltage.nominal", UPS_INFO_DECIMAL, offsetof(UPSEntry, config_input_voltage), 1 },
    { "output.current", UPS_INFO_DECIMAL, offsetof(UPSEntry, output_current), 10 },
    { "output.frequency", UPS_INFO_DECIMAL, offsetof(UPSEntry, output_freq), 10 },
    { "output.frequency.nominal", UPS_INFO_DECIMAL, offsetof(UPSEntry, config_output_freq), 10 },
    { "output.phases", UPS_INFO_DECIMAL, offsetof(UPSEntry, output_num_lines), 1 },
    { "output.power.nominal", UPS_INFO_DECIMAL, offsetof(UPSEntry, config_output_va), 1 },
    { "output.realpower", UPS_INFO_DECIMAL, offsetof(UPSEntry, output_power), 1 },
    { "output.realpower.nominal", UPS_INFO_DECIMAL, offsetof(UPSEntry, config_output_power), 1 },
    { "output.voltage", UPS_INFO_DECIMAL, offsetof(UPSEntry, output_voltage), 1 },
    { "output.voltage.nominal", UPS_INFO_DECIMAL, offsetof(UPSEntry, config_output_voltage), 1 },
    { "test.battery.stop", UPS_INFO_TEST_STATUS, offsetof(UPSEntry, test_status), 1 },
    { "test.battery.start", UPS_INFO_TEST_STATUS, offsetof(UPSEntry, test_status), 1 },
    { "test.battery.start.quick", UPS_INFO_TEST_STATUS, offsetof(UPSEntry, test_status), 1 },
    { "test.battery.start.deep", UPS_INFO_TEST_STATUS, offsetof(UPSEntry, test_status), 1 },
    { "ups.load", UPS_INFO_DECIMAL, offsetof(UPSEntry, output_load), 1 },
    { "ups.mfr", UPS_INFO_STRING, offsetof(UPSEntry, manufacturer), 0 },
    { "ups.model", UPS_INFO_STRING, offsetof(UPSEntry, model), 0 },
    { "ups.firmware", UPS_INFO_STRING, offsetof(UPSEntry, fw_version), 0 },
    { "ups.firmware.aux", UPS_INFO_STRING, offsetof(UPSEntry, fw_version_aux), 0 },
    { "ups.status", UPS_INFO_STATUS, offsetof(UPSEntry, status) },
    { "ups.timer.shutdown", UPS_INFO_DECIMAL, offsetof(UPSEntry, shutdown_delay), 1 },
    { "ups.timer.start", UPS_INFO_DECIMAL, offsetof(UPSEntry, startup_delay), 1 },
    { "ups.timer.reboot", UPS_INFO_DECIMAL, offsetof(UPSEntry, reboot_duration), 1 },
    { "ups.start.auto", UPS_INFO_BOOL, offsetof(UPSEntry, auto_restart), 1 },
    { "ups.beeper.status", UPS_INFO_BOOL, offsetof(UPSEntry, config_beeper), 1 },
    { "ups.test.result", UPS_INFO_STRING, offsetof(UPSEntry, test_result), 1 }
};

BatteryEntry *get_battery_list(void)
{
    return get_mib_cache(fetch_battery_list, free_battery_list, UPDATE_INTERVAL);
}

UPSEntry *get_ups_info(void)
{
    return get_mib_cache(fetch_ups_info, free, UPDATE_INTERVAL);
}

static void *fetch_ups_info(void)
{
    UPSEntry *ups = NULL;
    int sock = get_ups_sock();
    if (sock == -1) {
        syslog(LOG_DEBUG, "UPS socket unavailable");
        return NULL;
    }

    int offset = 0;
    while (strlen(ups_cmd_get) - offset > 0) {
        int written = write(sock, &ups_cmd_get[offset], strlen(ups_cmd_get) - offset);
        if (written <= 0) {
            goto err;
        }
        offset += written;
    }

    ups = (UPSEntry *) malloc(sizeof(UPSEntry));
    if (ups == NULL) {
        close(sock);
        return NULL;
    }
    memset(ups, 0, sizeof(UPSEntry));
    ups->status = UPS_STATUS_UNKNOWN;
    ups->output_source = UPS_OUTPUT_SOURCE_NONE;
    ups->test_status = UPS_TEST_RESULTS_NO_TESTS_INITIATED;
    ups->auto_restart = 2;
    ups->config_beeper = 1;

    FILE *f = fdopen(sock, "r");
    if (f == NULL)
        goto err;

    char buf[1024];
    while (buf == fgets(buf, sizeof(buf), f)) {
        if (parse_ups_buf(buf, ups))
            break;
    }

    fclose(f);
    return ups;
err:
    syslog(LOG_ERR, "failed to retrieve data from UPS daemon : %s", strerror(errno));
    close(sock);
    free(ups);
    return NULL;
}

static int get_ups_sock(void)
{
    DIR *dir = opendir(PATH_UPS_SOCK);
    if (dir == NULL)
        return -1;

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        snprintf(sa.sun_path, sizeof(sa.sun_path)-1, "%s/%s",
                PATH_UPS_SOCK, entry->d_name);
        struct stat s;
        if (stat(sa.sun_path, &s) == 0 && S_ISSOCK(s.st_mode))
            break;
        sa.sun_path[0] = '\0';
    }
    closedir(dir);

    if (sa.sun_path[0] == '\0')
        return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;

    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
        goto err;

    struct timeval tv;
    tv.tv_sec = SOCK_TIMEOUT;
    tv.tv_usec = 0;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof(tv)) < 0)
        goto err;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &tv, sizeof(tv)) < 0)
        goto err;

    return fd;
err:
    syslog(LOG_DEBUG, "failed to initialise UPS socket : %s", strerror(errno));
    close(fd);
    return -1;
}

static int parse_ups_buf(char *buf, UPSEntry *ups)
{
    if (!strncmp(buf, ups_cmd_done, strlen(ups_cmd_done)))
        return -1;
    if (strncmp(buf, ups_cmd_info, strlen(ups_cmd_info)))
        return 0;

    char *ptr;
    char *key = strtok_r(buf + sizeof(ups_cmd_info), " ", &ptr);
    char *val = strtok_r(NULL, "\n", &ptr);
    if (key == NULL || val == NULL)
        return 0;

    for (int i = 0; i < sizeof(ups_info) / sizeof(UPSInfo); i++) {
        if (!strcmp(ups_info[i].key, key)) {
            switch (ups_info[i].type) {
                case UPS_INFO_STRING: {
                    scan_ups_string((char *) ((char *) ups + ups_info[i].offset),
                        64, val);
                    break;
                }

                case UPS_INFO_DECIMAL: {
                    scan_ups_decimal((uint32_t *) ((char *) ups + ups_info[i].offset),
                        ups_info[i].multiplier, val);
                    break;
                }

                case UPS_INFO_BOOL: {
                    char status[32];
                    status[0] = '\0';
                    scan_ups_string(status, sizeof(status), val);
                    *((uint32_t *) ((char *) ups + ups_info[i].offset)) =
                        strncmp(status, "yes", 3) ? 1 : 2;
                    break;
                }

                case UPS_INFO_STATUS: {
                    char status[32];
                    status[0] = '\0';
                    scan_ups_string(status, sizeof(status), val);

                    char *tok = strtok_r(status, " ", &ptr);
                    while (tok != NULL) {
                        if (strncmp(tok, "OB", 2)) {
                            ups->output_source = UPS_OUTPUT_SOURCE_BATTERY;
                        } else if (strncmp(tok, "OL", 2)) {
                            ups->output_source = UPS_OUTPUT_SOURCE_NORMAL;
                        } else if (strncmp(tok, "LB", 2)) {
                            ups->status = UPS_STATUS_BATTERY_LOW;
                        } else if (strncmp(tok, "RB", 2) || strncmp(tok, "CHRG", 2)) {
                            ups->status = UPS_STATUS_BATTERY_NORMAL;
                        } else if (strncmp(tok, "DISCHRG", 2)) {
                            ups->output_source = UPS_OUTPUT_SOURCE_BATTERY;
                        }
                        tok = strtok_r(NULL, "\n", &ptr);
                    }
                    break;
                }

                case UPS_INFO_TEST_STATUS: {
                    if (strcmp(ups_info[i].key, "test.battery.stop")) {
                        ups->test_status = UPS_TEST_RESULTS_ABORTED;
                    } else {
                        ups->test_status = UPS_TEST_RESULTS_IN_PROGRESS;;
                    }
                    break;
                }
            }
            break;
        }
    }

    return 0;
}

static void scan_ups_string(char *buf, size_t buf_len, const char *src)
{
    const char *p = src;
    if (*p != '"')
        return;
    size_t i = 0;
    while (i < buf_len && *(++p) != '\n' && *p != '\0') {
        if (*p == '\\' && *(p + 1) == '"') {
            continue;
        } else {
            buf[i++] = *p;
        }
    }
    if (i) {
        buf[--i] = '\0';
    }
}

static void scan_ups_decimal(uint32_t *buf, int mult, const char *src)
{
    float f;
    if (sscanf(src, "\"%f\"", &f) == 1)
        *buf = (uint32_t) (f * mult);
}

static void *fetch_battery_list(void)
{
    BatteryEntry *head = NULL;
    BatteryEntry *tail = NULL;

    DIR *dir = opendir(PATH_BATTERY);
    if (dir == NULL)
        goto err;

    int i = 0;
    struct dirent *d;
    while ((d = readdir(dir))) {
        if (strncmp(d->d_name, "BAT", 3))
            continue;

        BatteryEntry *entry = malloc(sizeof(BatteryEntry));
        if (entry == NULL)
            continue;
        entry->index = ++i;
        entry->next = NULL;
        if (head == NULL) {
            head = entry;
            tail = entry;
        } else {
            tail->next = entry;
            tail = entry;
        }

        size_t man_len = fill_buffer(PATH_BATTERY_MANUFACTURER, d->d_name,
            entry->identifier, sizeof(entry->identifier));
        if (man_len > 0 && man_len < sizeof(entry->identifier))
            entry->identifier[man_len - 1] = ':';
        fill_buffer(PATH_BATTERY_MODEL, d->d_name, entry->identifier + man_len,
                sizeof(entry->identifier) - man_len);
        trim_string(entry->identifier);
        fill_buffer(PATH_BATTERY_SERIAL, d->d_name, entry->cell_identifier,
                sizeof(entry->cell_identifier));
        trim_string(entry->cell_identifier);
        entry->fw_version[0] = '\0';

        char buf[64];
        fill_buffer(PATH_BATTERY_TECHNOLOGY, d->d_name, buf, sizeof(buf));
        entry->technology = get_battery_technology(buf);

        fill_buffer(PATH_BATTERY_TYPE, d->d_name, buf, sizeof(buf));
        entry->type = get_battery_type(buf);

        if (read_unsigned_number(PATH_BATTERY_CYCLES, d->d_name,
                &entry->charging_cycle_count))
            entry->charging_cycle_count = 0xffffffff;

        if (read_unsigned_number(PATH_BATTERY_VOLTAGE_NOW, d->d_name,
                &entry->actual_voltage))
            entry->actual_voltage = 0xffffffff;
        else
            entry->actual_voltage /= 1000;

        if (read_unsigned_number(PATH_BATTERY_VOLTAGE_MIN, d->d_name,
                &entry->design_voltage))
            entry->design_voltage = 0xffffffff;
        else
            entry->design_voltage /= 1000;

        if (read_unsigned_number(PATH_BATTERY_CHARGE_NOW, d->d_name,
                &entry->actual_charge))
            entry->actual_charge = 0xffffffff;
        else
            entry->actual_charge /= 1000;

        if (read_unsigned_number(PATH_BATTERY_CHARGE_FULL, d->d_name,
                &entry->actual_capacity))
            entry->actual_capacity = 0xffffffff;
        else
            entry->actual_capacity /= 1000;

        if (read_unsigned_number(PATH_BATTERY_CHARGE_DESIGN, d->d_name,
                &entry->design_capacity))
            entry->design_capacity = 0xffffffff;
        else
            entry->design_capacity /= 1000;

        if (read_unsigned_number(PATH_BATTERY_CURRENT_NOW, d->d_name,
                (uint32_t *) &entry->actual_current))
            entry->actual_current = 0x7fffffff;
        else
            entry->actual_current /= 1000;

        if (read_unsigned_number(PATH_BATTERY_CURRENT_MAX, d->d_name,
                (uint32_t *) &entry->max_charging_current))
            entry->max_charging_current = 0x7fffffff;
        else
            entry->max_charging_current /= 1000;

        entry->trickle_charging_current = 0;

        if (read_unsigned_number(PATH_BATTERY_TEMPERATURE, d->d_name,
                (uint32_t *) &entry->temperature))
            entry->temperature = 0x7fffffff;

        fill_buffer(PATH_BATTERY_STATUS, d->d_name, buf, sizeof(buf));
        entry->oper_state = get_battery_oper_status(buf);
        entry->admin_state = BATTERY_ADMIN_STATE_NOT_SET;
        entry->num_cells = 0;
        entry->last_charging_cycle_time = 0;
    }

err:
    if (dir != NULL)
        closedir(dir);
    return head;
}

static void free_battery_list(void *list)
{
    BatteryEntry *e = list;

    while (e != NULL) {
        BatteryEntry *tmp = e->next;
        free(e);
        e = tmp;
    }
}

static size_t fill_buffer(char *path_dir, char *battery_name,
        char *dst_buf, size_t len)
{
    char path[1024];
    uint8_t *dst_buf_ptr = (uint8_t *) dst_buf;
    dst_buf[len - 1] = '\0';
    size_t dst_buf_len = len - 1;
    snprintf(path, sizeof(path), PATH_BATTERY"/%s/%s", battery_name, path_dir);
    if (read_from_file(path, &dst_buf_ptr, &dst_buf_len)) {
        dst_buf[0] = '\0';
        dst_buf_len = 0;
    } else if (dst_buf_len < len) {
        dst_buf[dst_buf_len - 1] = '\0';
    }
    return dst_buf_len;
}

static int read_unsigned_number(char *path_dir,
    char *battery_name, uint32_t *dst_buf)
{
    char path[1024];
    snprintf(path, sizeof(path), PATH_BATTERY"/%s/%s", battery_name, path_dir);
    if (read_unsigned_from_file(path, dst_buf)) {
        *dst_buf = 0;
        return -1;
    }
    return 0;
}

static enum BatteryType get_battery_type(char *type)
{
    if (type == NULL) {
        return BATTERY_TYPE_UNKNOWN;
    } else if (!strncmp(type, "Battery", 4)) {
        return BATTERY_TYPE_RECHARGEABLE;
    } else {
        return BATTERY_TYPE_OTHER;
    }
}

static enum BatteryTechnology get_battery_technology(char *tech)
{
    if (tech == NULL) {
        return BATTERY_TECH_UNKNOWN;
    } else if (!strncmp(tech, "NiMH", 4)) {
        return BATTERY_TECH_NICKEL_METAL_HYDRIDE;
    } else if (!strncmp(tech, "Li-ion", 6)) {
        return BATTERY_TECH_LITHIUM_ION;
    } else if (!strncmp(tech, "Li-poly", 7)) {
        return BATTERY_TECH_LITHIUM_POLYMER;
    } else if (!strncmp(tech, "LiFe", 4)) {
        return BATTERY_TECH_LITHIUM_IRON_DISULFIDE;
    } else if (!strncmp(tech, "NiCd", 4)) {
        return BATTERY_TECH_NICKEL_CADMIUM;
    } else if (!strncmp(tech, "LiMn", 4)) {
        return BATTERY_TECH_LITHIUM_MANGNESE_DIOXIDE;
    } else {
        return BATTERY_TECH_UNKNOWN;
    }
}

static enum BatteryOperState get_battery_oper_status(char *status)
{
    if (status == NULL) {
        return BATTERY_OPER_STATE_UNKNOWN;
    } else if (!strncmp(status, "Charging", 8)) {
        return BATTERY_OPER_STATE_CHARGING;
    } else if (!strncmp(status, "Discharging", 1)) {
        return BATTERY_OPER_STATE_DISCHARGING;
    } else if (!strncmp(status, "Not charging", 12)) {
        return BATTERY_OPER_STATE_NO_CHARGING;
    } else if (!strncmp(status, "Full", 4)) {
        return BATTERY_OPER_STATE_MAINTAINING_CHARGE;
    } else {
        return BATTERY_TECH_UNKNOWN;
    }
}
