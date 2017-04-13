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

#include <stddef.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <math.h>
#include <sensors/sensors.h>
#include <sensors/error.h>

#include "snmp-mib/sensors/sensor-cache.h"

#define SENSOR_VALUE_UNAVAILABLE 0xffffffff
#define SENSOR_FIXED_PRECISION 5

static enum EntitySensorDataType get_sensor_type(const sensors_feature *);
static uint32_t get_sensor_precision(const sensors_feature *);
static int get_input_value(const sensors_chip_name *, const sensors_subfeature *, double *);

static EntitySensorList sensor_list;

typedef struct {
    EntitySensor public;
    const sensors_chip_name *chip;
    const sensors_feature *feat;
} EntityLmSensor;

int init_sensor_cache(void)
{
    sensor_list.len = 0;
    int cur_max = 16;
    sensor_list.list = malloc(sizeof(EntitySensor *) * cur_max);
    if (sensor_list.list == NULL)
        return -1;

    int err = sensors_init(NULL);
    if (err) {
        syslog(LOG_ERR, "sensor init failed : %s", sensors_strerror(err));
        return -1;
    }

    const sensors_chip_name *chip;
    int chip_nr = 0;
    while ((chip = sensors_get_detected_chips(NULL, &chip_nr))) {
        const char *adap_name = sensors_get_adapter_name(&chip->bus);
        if (adap_name == NULL) {
            syslog(LOG_ERR, "invalid adapter name");
            continue;
        }

        const sensors_feature *feat;
        int feat_nr = 0;
        while ((feat = sensors_get_features(chip, &feat_nr))) {
            enum EntitySensorDataType type = get_sensor_type(feat);
            if (type == 0)
                continue;
            char *label = sensors_get_label(chip, feat);
            if (label == NULL) {
                syslog(LOG_ERR, "invalid sensor feature label for %s", feat->name);
                continue;
            }

            EntityLmSensor *sensor = malloc(sizeof(EntityLmSensor));
            if (sensor == NULL)
                continue;
            if (sensor_list.len <= cur_max) {
                EntitySensor **new_list = realloc(sensor_list.list, cur_max << 1);
                if (new_list == NULL) {
                    free(label);
                    goto err;
                }
                sensor_list.list = new_list;
                cur_max <<= 1;
            }
            sensor_list.list[sensor_list.len++] = (EntitySensor *) sensor;
            sensor->public.entity_index = (chip_nr << 16) | feat_nr;
            snprintf(sensor->public.description,
                sizeof(sensor->public.description), "%s : %s", adap_name, label);
            sensor->public.value = SENSOR_VALUE_UNAVAILABLE;
            sensor->public.status = SENSOR_STATUS_UNAVAILABLE;
            sensor->public.data_type = type;
            sensor->public.precision = get_sensor_precision(feat);
            sensor->public.scale = 0;
            sensor->chip = chip;
            sensor->feat = feat;
            free(label);
        }
    }
    return 0;

err:
    free(sensor_list.list);
    sensor_list.len = 0;
    return -1;
}

int finish_sensor_cache(void)
{
    if (sensor_list.list != NULL) {
        for (int i = 0; i < sensor_list.len; i++) {
            free(sensor_list.list[i]);
        }
        free(sensor_list.list);
    }
    sensors_cleanup();
    return 0;
}

EntitySensorList *get_sensor_cache(void)
{
    return &sensor_list;
}

int update_sensor(EntitySensor *sensor)
{
    EntityLmSensor *priv = (EntityLmSensor *) sensor;
    int subfeature;
    switch (priv->feat->type) {
        case SENSORS_FEATURE_IN: {
            subfeature = SENSORS_SUBFEATURE_IN_INPUT;
            break;
        }

        case SENSORS_FEATURE_VID: {
            subfeature = SENSORS_SUBFEATURE_VID;
            break;
        }

        case SENSORS_FEATURE_TEMP: {
            subfeature = SENSORS_SUBFEATURE_TEMP_INPUT;
            break;
        }

        case SENSORS_FEATURE_POWER: {
            subfeature = SENSORS_SUBFEATURE_POWER_INPUT;
            break;
        }

        case SENSORS_FEATURE_ENERGY: {
            subfeature = SENSORS_SUBFEATURE_ENERGY_INPUT;
            break;
        }

        case SENSORS_FEATURE_CURR: {
            subfeature = SENSORS_SUBFEATURE_CURR_INPUT;
            break;
        }

        case SENSORS_FEATURE_FAN: {
            subfeature = SENSORS_SUBFEATURE_FAN_INPUT;
            break;
        }

        case SENSORS_FEATURE_HUMIDITY: {
            subfeature = SENSORS_SUBFEATURE_HUMIDITY_INPUT;
            break;
        }

        case SENSORS_FEATURE_BEEP_ENABLE: {
            subfeature = SENSORS_SUBFEATURE_BEEP_ENABLE;
            break;
        }

        case SENSORS_FEATURE_INTRUSION: {
            subfeature = SENSORS_SUBFEATURE_INTRUSION_ALARM;
            break;
        }

        default: {
            sensor->status = SENSOR_STATUS_UNAVAILABLE;
            sensor->value = SENSOR_VALUE_UNAVAILABLE;
            return -1;
        }
    }

    const sensors_subfeature *sf =
            sensors_get_subfeature(priv->chip, priv->feat, subfeature);
    double val;
    if (!subfeature) {
        sensor->status = SENSOR_STATUS_UNAVAILABLE;
        sensor->value = SENSOR_VALUE_UNAVAILABLE;
    } else if (get_input_value(priv->chip, sf, &val)) {
        sensor->status = SENSOR_STATUS_NON_OPERATIONAL;
        sensor->value = SENSOR_VALUE_UNAVAILABLE;
    } else {
        sensor->status = SENSOR_STATUS_OK;
        if (sensor->precision == SENSOR_FIXED_PRECISION) {
            sensor->value = (uint32_t) (val * pow(10,SENSOR_FIXED_PRECISION));
        } else if (priv->feat->type == SENSORS_FEATURE_HUMIDITY) {
            sensor->value = (uint32_t) (val * 100);
        } else if (sensor->data_type == SENSOR_DATA_TYPE_TRUTH_VALUE) {
            sensor->value = val ? 1 : 0;
        } else {
            sensor->value = (uint32_t) val;
        }
    }

    return 0;
}

static int get_input_value(const sensors_chip_name *chip,
        const sensors_subfeature *sub, double *val)
{
    int err = sensors_get_value(chip, sub->number, val);
    if (err && err != -SENSORS_ERR_ACCESS_R)
        syslog(LOG_WARNING, "failed to fetch subfeature %s : %s",
            sub->name, sensors_strerror(err));
    return err;
}

static enum EntitySensorDataType get_sensor_type(const sensors_feature *feat)
{
    switch (feat->type) {
        case SENSORS_FEATURE_IN: {
            return SENSOR_DATA_TYPE_VOLTS_AC;
        }

        case SENSORS_FEATURE_VID: {
            return SENSOR_DATA_TYPE_VOLTS_DC;
        }

        case SENSORS_FEATURE_FAN: {
            return SENSOR_DATA_TYPE_RPM;
        }

        case SENSORS_FEATURE_TEMP: {
            return SENSOR_DATA_TYPE_CELSIUS;
        }

        case SENSORS_FEATURE_POWER: {
            return SENSOR_DATA_TYPE_WATTS;
        }

        case SENSORS_FEATURE_ENERGY: {
            return SENSOR_DATA_TYPE_OTHER;
        }

        case SENSORS_FEATURE_CURR: {
            return SENSOR_DATA_TYPE_AMPERES;
        }

        case SENSORS_FEATURE_HUMIDITY: {
            return SENSOR_DATA_TYPE_PERCENT_RH;
        }

        case SENSORS_FEATURE_BEEP_ENABLE:
        case SENSORS_FEATURE_INTRUSION: {
            return SENSOR_DATA_TYPE_TRUTH_VALUE;
        }

        default: {
            return 0;
        }
    }
}

static uint32_t get_sensor_precision(const sensors_feature *feat)
{
    switch (feat->type) {
        case SENSORS_FEATURE_FAN:
        case SENSORS_FEATURE_HUMIDITY:
        case SENSORS_FEATURE_BEEP_ENABLE:
        case SENSORS_FEATURE_INTRUSION: {
            return 0;
        }

        default: {
            return SENSOR_FIXED_PRECISION;
        }
    }
}
