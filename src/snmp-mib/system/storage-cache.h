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

#ifndef SRC_SNMP_MIB_SYSTEM_STORAGE_CACHE_H_
#define SRC_SNMP_MIB_SYSTEM_STORAGE_CACHE_H_

typedef struct StorageEntry {
    uint32_t index;
    OID type;
    char descr[64];
    uint32_t allocation_units;
    uint32_t size;
    uint32_t used;
    struct StorageEntry *next;
} StorageEntry;

/**
 * @internal
 * get_storage_list - returns list of storage entries
 *
 * @return list of storage entries, or NULL if not available.
 */
StorageEntry *get_storage_list(void);

#endif /* SRC_SNMP_MIB_SYSTEM_STORAGE_CACHE_H_ */
