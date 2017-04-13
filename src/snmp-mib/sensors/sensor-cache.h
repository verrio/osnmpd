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

#ifndef SRC_SNMP_MIB_SENSORS_SENSOR_CACHE_H_
#define SRC_SNMP_MIB_SENSORS_SENSOR_CACHE_H_

#include <stdint.h>

enum EntitySensorDataType {
    SENSOR_DATA_TYPE_OTHER = 1,
    SENSOR_DATA_TYPE_UNKNOWN = 2,
    SENSOR_DATA_TYPE_VOLTS_AC = 3,
    SENSOR_DATA_TYPE_VOLTS_DC = 4,
    SENSOR_DATA_TYPE_AMPERES = 5,
    SENSOR_DATA_TYPE_WATTS = 6,
    SENSOR_DATA_TYPE_HERTZ = 7,
    SENSOR_DATA_TYPE_CELSIUS = 8,
    SENSOR_DATA_TYPE_PERCENT_RH = 9,
    SENSOR_DATA_TYPE_RPM = 10,
    SENSOR_DATA_TYPE_CMM = 11,
    SENSOR_DATA_TYPE_TRUTH_VALUE = 12
};

enum EntitySensorStatus {
    SENSOR_STATUS_OK = 1,
    SENSOR_STATUS_UNAVAILABLE = 2,
    SENSOR_STATUS_NON_OPERATIONAL = 3
};

typedef struct {
    uint32_t entity_index;
    uint32_t value;
    uint32_t scale;
    uint32_t precision;
    enum EntitySensorDataType data_type;
    enum EntitySensorStatus status;
    char description[64];
} EntitySensor;

typedef struct {
    EntitySensor **list;
    size_t len;
} EntitySensorList;

/**
 * @internal
 * init_sensor_cache - initialise the sensor cache
 *
 * @return 0 on success, -1 on error.
 */
int init_sensor_cache(void);

/**
 * @internal
 * finish_sensor_cache - finalise the sensor cache
 *
 * @return 0 on success, -1 on error.
 */
int finish_sensor_cache(void);

/**
 * @internal
 * get_sensor_cache - returns list of sensor entries
 *
 * @return list of sensor entries, or NULL if not available.
 */
EntitySensorList *get_sensor_cache(void);

/**
 * @internal
 * update_sensor - update sensor value for given entry.
 *
 * @param sensor IN/OUT - sensor to be updated.
 *
 * @return 0 on success, -1 on error.
 */
int update_sensor(EntitySensor *sensor);

#endif /* SRC_SNMP_MIB_SENSORS_SENSOR_CACHE_H_ */
