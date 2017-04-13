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

#ifndef SRC_SNMP_CORE_SNMP_DATE_TIME_H_
#define SRC_SNMP_CORE_SNMP_DATE_TIME_H_

#include <stdint.h>
#include "snmp-core/snmp-types.h"

/*
 * SMI encoding of date/time fields according to the textual convention of RFC 2579
 *
 * DateAndTime ::= TEXTUAL-CONVENTION
 *     DISPLAY-HINT "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"
 *     STATUS       current
 *     DESCRIPTION
 *             "A date-time specification.
 *
 *             field  octets  contents                  range
 *             -----  ------  --------                  -----
 *               1      1-2   year*                     0..65536
 *               2       3    month                     1..12
 *               3       4    day                       1..31
 *               4       5    hour                      0..23
 *               5       6    minutes                   0..59
 *               6       7    seconds                   0..60
 *                            (use 60 for leap-second)
 *               7       8    deci-seconds              0..9
 *               8       9    direction from UTC        '+' / '-'
 *               9      10    hours from UTC*           0..13
 *              10      11    minutes from UTC          0..59
 *
 *             * Notes:
 *             - the value of year is in network-byte order
 *             - daylight saving time in New Zealand is +13
 *
 *             For example, Tuesday May 26, 1992 at 1:30:15 PM EDT would be
 *             displayed as:
 *
 *
 *             Note that if only local time is known, then timezone
 *             information (fields 8-10) is not present."
 *     SYNTAX       OCTET STRING (SIZE (8 | 11))
 */

#define SMI_DATE_AND_TIME_LEN 8
#define SMI_DATE_AND_TIME_LEN_EX 11

/**
 * @internal
 * decode_timestamp - Extracts a millis timestamp from the given variable binding.
 *
 * @param timestamp OUT - output buffer.
 * @param binding IN - input variable binding.
 *
 * @return 0 on success, -1 on error.
 */
int decode_timestamp(uint64_t *timestamp, SnmpVariableBinding *binding);

/**
 * @internal
 * encode_date_time - Encodes the given millis timestamp to a DateAndTime field.
 *
 * @param timestamp IN - input timestamp (millis).
 * @param binding OUT - output variable binding.
 *
 * @return 0 on success, -1 on error.
 */
int encode_date_time(uint64_t timestamp, SnmpVariableBinding *binding);

#endif /* SRC_SNMP_CORE_SNMP_DATE_TIME_H_ */
