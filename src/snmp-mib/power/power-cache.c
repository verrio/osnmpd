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

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/power/power-cache.h"

#define UPDATE_INTERVAL 8

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

static void *fetch_battery_list(void);
static void free_battery_list(void *);
static enum BatteryTechnology get_battery_technology(char *);
static enum BatteryType get_battery_type(char *);
static enum BatteryOperState get_battery_oper_status(char *);
static size_t fill_buffer(char *, char *, char *, size_t);
static int read_unsigned_number(char *, char *, uint32_t *);

BatteryEntry *get_battery_list(void)
{
    return get_mib_cache(fetch_battery_list, free_battery_list, UPDATE_INTERVAL);
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
