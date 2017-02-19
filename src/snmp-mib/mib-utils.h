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

#ifndef SRC_SNMP_MIB_MIB_UTILS_H_
#define SRC_SNMP_MIB_MIB_UTILS_H_

/**
 * @internal
 * search_int_indices - search for next integer row
 *
 * @param index_len  IN - length of index array
 * @param index_min  IN - array containing minimum of indices
 * @param index_max  IN - array containing max of indices
 * @param row        OUT - destination for new row
 * @param cur        IN - OID of query
 * @param cur_len    IN - length of OID
 * @param next       IN - 1 if successor of given OID should be returned,
 * 0 if exact match is required.
 *
 * @return returns 0 on success, or -1 if no match found.
 */
int search_int_indices(const size_t index_len, const uint32_t index_min[],
        const uint32_t index_max[], uint32_t row[], const SubOID *cur,
        const size_t cur_len, const int next);

/**
 * @internal
 * bsearch_string_indices - binary search rows with string index
 *
 * @param rows       IN - array containing row indices
 * @param row_count  IN - array size
 * @param cur        IN - OID of query
 * @param cur_len    IN - length of OID
 * @param next       IN - 1 if successor of given OID should be returned,
 * 0 if exact match is required.
 *
 * @return matching row index, or -1 if no match found.
 */
int bsearch_string_indices(const char *rows[], const int row_count,
        const SubOID *cur, const size_t cur_len, const int next);

/**
 * @internal
 * bsearch_oid_indices - binary search rows with OID index
 *
 * @param rows       IN - array containing row indices
 * @param row_len    IN - array containing length of row OIDs
 * @param row_count  IN - array size
 * @param cur        IN - OID of query
 * @param cur_len    IN - length of OID
 * @param next       IN - 1 if successor of given OID should be returned,
 * 0 if exact match is required.
 *
 * @return matching row index, or -1 if no match found.
 */
int bsearch_oid_indices(const SubOID *rows[], const size_t row_len[],
        const int row_count, const SubOID *cur, const size_t cur_len, const int next);

/**
 * @internal
 * lsearch_string_indices - linear search (unsorted) rows with string index
 *
 * @param rows       IN - array containing row indices
 * @param row_count  IN - array size
 * @param cur        IN - OID of query
 * @param cur_len    IN - length of OID
 * @param next       IN - 1 if successor of given OID should be returned,
 * 0 if exact match is required.
 *
 * @return matching row index, or -1 if no match found.
 */
int lsearch_string_indices(const char *rows[], const int row_count,
        const SubOID *cur, const size_t cur_len, const int next);

/**
 * @internal
 * cmp_index_to_array - compare OID index to a byte array
 *
 * @param arr      IN - array to be compared against
 * @param arr_len  IN - array size
 * @param val      IN - OID index
 * @param val_len  IN - length of index
 *
 * @return -1 if index is smaller than byte array, 1 if larger, 0 if equal.
 */
int cmp_index_to_array(const uint8_t *arr, const size_t arr_len,
        const SubOID *val, const size_t val_len);

/**
 * @internal
 * cmp_index_to_oid - compare OID index to a static OID
 *
 * @param oid      IN - OID to be compared against
 * @param oid_len  IN - OID length
 * @param val      IN - index
 * @param val_len  IN - length of index
 *
 * @return -1 if index is smaller than the OID, 1 if larger, 0 if equal.
 */
int cmp_index_to_oid(const SubOID *oid, const size_t oid_len,
        const SubOID *val, const size_t val_len);

/**
 * @internal
 * fill_row_index_oid - extend OID with subOID row index
 *
 * @param oid          OUT - output OID
 * @param row_indx     IN - row index
 * @param row_indx_len IN - row index length
 *
 * @return -1 if index is too large, 0 on succes.
 */
int fill_row_index_oid(OID *oid, const SubOID *row_indx,
        const size_t row_indx_len);

/**
 * @internal
 * fill_row_index_string - extend OID with string row index
 *
 * @param oid          OUT - output OID
 * @param row_indx     IN - row index
 * @param row_indx_len IN - row index length
 *
 * @return -1 if index is too large, 0 on succes.
 */
int fill_row_index_string(OID *oid, const uint8_t *row_indx,
        const size_t row_indx_len);

#endif /* SRC_SNMP_MIB_MIB_UTILS_H_ */
