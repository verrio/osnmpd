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

#include "snmp-core/snmp-types.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"

int search_int_indices(const size_t index_len, const uint32_t index_min[],
        const uint32_t index_max[], uint32_t row[], const SubOID *cur,
        const size_t cur_len, const int next)
{
    int i;
    for (i = 0; i < index_len; i++) {
        if (i + 1 > cur_len || cur[i] < index_min[i]) {
            if (!next) {
                return -1;
            } else {
                goto complete_row;
            }
        } else if (cur[i] > index_max[i]) {
            if (!next || i == 0 || row[i-1] >= index_max[i-1]) {
                return -1;
            } else {
                row[i-1]++;
                goto complete_row;
            }
        } else {
            if (next && i + 1 >= index_len) {
                if (cur[i] < index_max[i]) {
                    row[i] = cur[i] + 1;
                } else if (i > 0 && row[i-1] < index_max[i-1]) {
                    row[i-1]++;
                    row[i] = index_min[i];
                } else {
                    return -1;
                }
            } else {
                row[i] = cur[i];
            }
        }
    }

    return (next || cur_len == index_len) ? 0 : -1;

complete_row:
    for (; i < index_len; i++) {
        row[i] = index_min[i];
    }
    return 0;
}

int bsearch_string_indices(const char *rows[], const int row_count,
    const SubOID *cur, const size_t cur_len, const int next)
{
    if (row_count <= 0) {
        return -1;
    } else if (cur_len == 0) {
        return next ? 0 : -1;
    }

    int low = 0;
    int high = row_count - 1;

    while (low <= high) {
        int i = low + (high - low) / 2;
        int len = strlen(rows[i]);
        switch (cmp_index_to_array((uint8_t *) rows[i], len, cur, cur_len)) {
            case 0: {
                return next ? (i < row_count - 1 ? i + 1 : -1) : i;
            }

            case -1: {
                high = i - 1;
                break;
            }

            case 1: {
                low = i + 1;
            }
        }
    }

    return next && low < row_count ? low : -1;
}

int bsearch_oid_indices(const SubOID *rows[], const size_t row_len[],
    const int row_count, const SubOID *cur, const size_t cur_len, const int next)
{
    if (row_count <= 0) {
        return -1;
    } else if (cur_len == 0) {
        return next ? 0 : -1;
    }

    int low = 0;
    int high = row_count - 1;

    while (low <= high) {
        int i = low + (high - low) / 2;
        switch (cmp_index_to_oid(rows[i], row_len[i], cur, cur_len)) {
            case 0: {
                return next ? (i < row_count - 1 ? i + 1 : -1) : i;
            }

            case -1: {
                high = i - 1;
                break;
            }

            case 1: {
                low = i + 1;
            }
        }
    }

    return next && low < row_count ? low : -1;
}

int lsearch_string_indices(const char *rows[], const int row_count,
    const SubOID *cur, const size_t cur_len, const int next)
{
    if (row_count <= 0) {
        return -1;
    }

    int idx = -1;

    for (int i = 0; i < row_count; i++) {
        switch (cmp_index_to_array((uint8_t *) rows[i], strlen(rows[i]), cur, cur_len)) {
            case 0: {
                if (!next) {
                    return i;
                }
                break;
            }

            case -1: {
                if (next && (idx == -1 ||
                        strlen(rows[idx]) > strlen(rows[i]) ||
                        (strlen(rows[idx]) == strlen(rows[i])
                                && strcmp(rows[idx], rows[i]) > 0))) {
                    idx = i;
                }
                break;
            }
        }
    }

    return next ? idx : -1;
}

int cmp_index_to_array(const uint8_t *arr, const size_t arr_len,
    const SubOID *val, const size_t val_len)
{
    if (val_len == 0 || val[0] < arr_len) {
        return -1;
    } else if (val[0] > arr_len) {
        return 1;
    }

    for (int i = 0; i < min(arr_len, val_len - 1); i++) {
        if (val[i + 1] < arr[i]) {
            return 1;
        } else if (val[i + 1] > arr[i]) {
            return -1;
        }
    }

    if (val_len < arr_len + 1) {
        return -1;
    } else if (val_len > arr_len + 1) {
        return 1;
    } else {
        return 0;
    }
}

int cmp_index_to_oid(const SubOID *oid, const size_t oid_len,
    const SubOID *val, const size_t val_len)
{
    for (int i = 0; i < min(oid_len, val_len); i++) {
        if (oid[i] < val[i]) {
            return 1;
        } else if (oid[i] > val[i]) {
            return -1;
        }
    }

    if (oid_len < val_len) {
        return 1;
    } else if (oid_len > val_len) {
        return -1;
    }

    return 0;
}

int fill_row_index_oid(OID *oid, const SubOID *row_indx, const size_t row_indx_len)
{
    if (MAX_OID_LEN - oid->len < row_indx_len) {
        return -1;
    }
    for (int i = 0; i < row_indx_len; i++) {
        oid->subid[oid->len++] = row_indx[i];
    }
    return 0;
}

int fill_row_index_string(OID *oid, const uint8_t *row_indx,
        const size_t row_indx_len)
{
    if (MAX_OID_LEN - oid->len < row_indx_len + 1) {
        return -1;
    }
    oid->subid[oid->len++] = row_indx_len;
    for (int i = 0; i < row_indx_len; i++) {
        oid->subid[oid->len++] = row_indx[i];
    }
    return 0;
}
