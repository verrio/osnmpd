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

#ifndef SRC_SNMP_MIB_SYSTEM_DEVICE_CACHE_H_
#define SRC_SNMP_MIB_SYSTEM_DEVICE_CACHE_H_

#define DEVICE_ID_PREFIX_CPU 0x00000000
#define DEVICE_ID_PREFIX_NETWORK 0x00A00000
#define DEVICE_ID_PREFIX_PRINTER 0x00B00000
#define DEVICE_ID_PREFIX_STORAGE 0x00C00000

enum DeviceType {
    DEVICE_TYPE_PROCESSOR = 3,
    DEVICE_TYPE_NETWORK = 4,
    DEVICE_TYPE_PRINTER = 5,
    DEVICE_TYPE_STORAGE = 6
};

enum DeviceStatus {
    DEVICE_STATUS_UNKNOWN = 1,
    DEVICE_STATUS_RUNNING = 2,
    DEVICE_STATUS_WARNING = 3,
    DEVICE_STATUS_TESTING = 4,
    DEVICE_STATUS_DOWN = 5
};

enum DeviceStorageAccess {
    DEVICE_STORAGE_READ_WRITE = 1,
    DEVICE_STORAGE_READ_ONLY = 2
};

enum DeviceStorageMedia {
    DEVICE_STORAGE_MEDIA_OTHER = 1,
    DEVICE_STORAGE_MEDIA_UNKNOWN = 2,
    DEVICE_STORAGE_MEDIA_HARD_DISK = 3,
    DEVICE_STORAGE_MEDIA_FLOPPY_DISK = 4,
    DEVICE_STORAGE_MEDIA_OPTICAL_DISK_ROM = 5,
    DEVICE_STORAGE_MEDIA_OPTICAL_DISK_WORM = 6,
    DEVICE_STORAGE_MEDIA_OPTICAL_DISK_RW = 7,
    DEVICE_STORAGE_MEDIA_RAM_DISK = 8
};

typedef struct PartitionEntry {
    uint32_t device_id;
    uint32_t partition_id;
    char label[64];
    char uuid[64];
    uint32_t size;
    struct PartitionEntry *next;
} PartitionEntry;

typedef struct {
    uint32_t id;
    enum DeviceType type;
    char descr[64];
    enum DeviceStatus status;
    uint32_t errors;
} DeviceEntry;

typedef struct {
    DeviceEntry device;
    uint32_t load;
} DeviceProcessorEntry;

typedef struct {
    DeviceEntry device;
    uint32_t iface_id;
} DeviceIfaceEntry;

typedef struct {
    DeviceEntry device;
    enum DeviceStorageAccess access;
    enum DeviceStorageMedia media;
    int removable;
    uint32_t capacity;
    PartitionEntry *partitions;
} DeviceStorageEntry;

typedef struct {
    size_t len;
    size_t max_len;
    DeviceEntry **arr;
} DeviceList;

/**
 * @internal
 * get_device_list - returns list of available devices
 *
 * @return list of devices, or NULL if not available.
 */
DeviceList *get_device_list(void);

#endif /* SRC_SNMP_MIB_SYSTEM_DEVICE_CACHE_H_ */
