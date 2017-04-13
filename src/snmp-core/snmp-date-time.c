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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

#include "snmp-core/snmp-date-time.h"

int decode_timestamp(uint64_t *timestamp, SnmpVariableBinding *binding)
{
    switch (binding->type) {
        /* hundreths timestamp */
        case SMI_TYPE_TIME_TICKS: {
            *timestamp = binding->value.unsigned_integer * 10;
            break;
        }

        /* seconds timestamp */
        case SMI_TYPE_COUNTER_32: {
            *timestamp = binding->value.unsigned_integer * 1000;
            break;
        }

        /* millis timestamp */
        case SMI_TYPE_COUNTER_64: {
            *timestamp = binding->value.counter64;
            break;
        }

        /* DateAndTime field */
        case SMI_TYPE_OCTET_STRING: {
            struct tm parts;
            memset(&parts, 0, sizeof(struct tm));
            int deciseconds = 0;
            int offset = 0;

            if (GET_OCTET_STRING_LEN(binding) == SMI_DATE_AND_TIME_LEN ||
                GET_OCTET_STRING_LEN(binding) == SMI_DATE_AND_TIME_LEN_EX) {
                uint8_t *encoded = GET_OCTET_STRING(binding);
                parts.tm_year = ((encoded[0] << 8) + encoded[1]) - 1900;
                parts.tm_mon = encoded[2] - 1;
                parts.tm_mday = encoded[3];
                parts.tm_hour = encoded[4];
                parts.tm_min = encoded[5];
                parts.tm_sec = encoded[6];
                deciseconds = encoded[7];
                if (GET_OCTET_STRING_LEN(binding) == SMI_DATE_AND_TIME_LEN_EX) {
                    int offset = 1000 * 60 * (encoded[9] * 60 + encoded[10]);
                    if (encoded[8] == '-') {
                        offset *= -1;
                    } else if (encoded[8] != '+') {
                        return -1;
                    }
                }
            } else {
                return -1;
            }

            time_t seconds = mktime(&parts);
            if (seconds == (time_t) -1) {
                return -1;
            }
            *timestamp = seconds * 1000 + deciseconds * 100 + offset;
            break;
        }

        default: {
            return -1;
        }
    }

    return 0;
}

int encode_date_time(uint64_t timestamp, SnmpVariableBinding *binding)
{
    time_t time_sec = timestamp / 1000;
    struct tm parts;
    if (localtime_r(&time_sec, &parts) == NULL) {
        return -1;
    }

    GET_OCTET_STRING(binding) = malloc(SMI_DATE_AND_TIME_LEN * sizeof(uint8_t));
    if (GET_OCTET_STRING(binding) == NULL) {
        return -1;
    }

    binding->type = SMI_TYPE_OCTET_STRING;
    GET_OCTET_STRING_LEN(binding) = SMI_DATE_AND_TIME_LEN;
    GET_OCTET_STRING(binding)[0] = (1900 + parts.tm_year) >> 8;
    GET_OCTET_STRING(binding)[1] = 0xff & (1900 + parts.tm_year);
    GET_OCTET_STRING(binding)[2] = 1 + parts.tm_mon;
    GET_OCTET_STRING(binding)[3] = parts.tm_mday;
    GET_OCTET_STRING(binding)[4] = parts.tm_hour;
    GET_OCTET_STRING(binding)[5] = parts.tm_min;
    GET_OCTET_STRING(binding)[6] = parts.tm_sec;
    GET_OCTET_STRING(binding)[7] = timestamp / 100 % 10;
    return 0;
}
