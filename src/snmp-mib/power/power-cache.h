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

#ifndef SRC_SNMP_MIB_SYSTEM_POWER_CACHE_H_
#define SRC_SNMP_MIB_SYSTEM_POWER_CACHE_H_

enum BatteryType {
    BATTERY_TYPE_UNKNOWN = 1,
    BATTERY_TYPE_OTHER = 2,
    BATTERY_TYPE_PRIMARY = 3,
    BATTERY_TYPE_RECHARGEABLE = 4,
    BATTERY_TYPE_CAPACITOR = 5
};

enum BatteryTechnology {
    BATTERY_TECH_UNKNOWN = 1,
    BATTERY_TECH_OTHER = 2,
    BATTERY_TECH_ZINC_CARBON = 3,
    BATTERY_TECH_ZINC_CHLORIDE = 4,
    BATTERY_TECH_NICKEL_OXYHYDROXIDE = 5,
    BATTERY_TECH_LITHIUM_COPPER_OXIDE = 6,
    BATTERY_TECH_LITHIUM_IRON_DISULFIDE = 7,
    BATTERY_TECH_LITHIUM_MANGNESE_DIOXIDE = 8,
    BATTERY_TECH_ZINC_AIR = 9,
    BATTERY_TECH_SILVER_OXIDE = 10,
    BATTERY_TECH_ALKALINE = 11,
    BATTERY_TECH_LEAD_ACID = 12,
    BATTERY_TECH_VALVE_REGULATED_LEAD_ACID_GEL = 13,
    BATTERY_TECH_VALVE_REGULATED_LEAD_ACID_AGM = 14,
    BATTERY_TECH_NICKEL_CADMIUM = 15,
    BATTERY_TECH_NICKEL_METAL_HYDRIDE = 16,
    BATTERY_TECH_NICKEL_ZINC = 17,
    BATTERY_TECH_LITHIUM_ION = 18,
    BATTERY_TECH_LITHIUM_POLYMER = 19,
    BATTERY_TECH_DOUBLE_LAYER_CAPACITOR = 20
};

enum BatteryOperState {
    BATTERY_OPER_STATE_UNKNOWN = 1,
    BATTERY_OPER_STATE_CHARGING = 2,
    BATTERY_OPER_STATE_MAINTAINING_CHARGE = 3,
    BATTERY_OPER_STATE_NO_CHARGING = 4,
    BATTERY_OPER_STATE_DISCHARGING = 5
};

enum BatteryAdminState {
    BATTERY_ADMIN_STATE_NOT_SET = 1,
    BATTERY_ADMIN_STATE_CHARGE = 2,
    BATTERY_ADMIN_STATE_DO_NOT_CHARGE = 3,
    BATTERY_ADMIN_STATE_DISCHARGE = 4
};

typedef struct BatteryEntry {
    uint32_t index;
    char identifier[64];
    char cell_identifier[64];
    char fw_version[64];
    enum BatteryType type;
    enum BatteryTechnology technology;
    enum BatteryOperState oper_state;
    enum BatteryAdminState admin_state;
    uint32_t design_voltage;
    uint32_t design_capacity;
    uint32_t actual_capacity;
    uint32_t actual_charge;
    uint32_t actual_voltage;
    int32_t actual_current;
    int32_t temperature;
    uint32_t num_cells;
    uint32_t max_charging_current;
    uint32_t trickle_charging_current;
    uint32_t charging_cycle_count;
    uint64_t last_charging_cycle_time;
    struct BatteryEntry *next;
} BatteryEntry;

/**
 * @internal
 * get_battery_list - returns list of battery entries
 *
 * @return list of battery entries, or NULL if not available.
 */
BatteryEntry *get_battery_list(void);

#endif /* SRC_SNMP_MIB_SYSTEM_POWER_CACHE_H_ */
