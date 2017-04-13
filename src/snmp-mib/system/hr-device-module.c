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
#include <unistd.h>
#include <stdio.h>

#include "snmp-agent/mib-tree.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/system/device-cache.h"
#include "snmp-mib/system/hr-device-module.h"

enum HRDeviceMIBObjects {
    HR_DEVICE_TABLE = 2,
    HR_PROCESSOR_TABLE = 3,
    HR_NETWORK_TABLE = 4,
    HR_PRINTER_TABLE = 5,
    HR_DISK_STORAGE_TABLE = 6,
    HR_PARTITION_TABLE = 7,
    HR_FS_TABLE = 8
};

enum HRDeviceTableColumns {
    HR_DEVICE_INDEX = 1,
    HR_DEVICE_TYPE = 2,
    HR_DEVICE_DESCR = 3,
    HR_DEVICE_ID = 4,
    HR_DEVICE_STATUS = 5,
    HR_DEVICE_ERRORS = 6
};

enum HRProcessorTableColumns {
    HR_PROCESSOR_FRW_ID = 1,
    HR_PROCESSOR_LOAD = 2
};

enum HRNetworkTableColumns {
    HR_NETWORK_IF_INDEX = 1
};

enum HRPrinterTableColumns {
    HR_PRINTER_STATUS = 1,
    HR_PRINTER_DETECTED_ERROR_STATE = 2
};

enum HRDiskStorageTableColumns {
    HR_DISK_STORAGE_ACCESS = 1,
    HR_DISK_STORAGE_MEDIA = 2,
    HR_DISK_STORAGE_REMOVEBLE = 3,
    HR_DISK_STORAGE_CAPACITY = 4
};

enum HRPartitionTableColumns {
    HR_PARTITION_INDEX = 1,
    HR_PARTITION_LABEL = 2,
    HR_PARTITION_ID = 3,
    HR_PARTITION_SIZE = 4,
    HR_PARTITION_FS_INDEX = 5
};

enum HRFileSystemTableColumns {
    HR_FS_INDEX = 1,
    HR_FS_MOUNT_POINT = 2,
    HR_FS_REMOTE_MOUNT_POINT = 3,
    HR_FS_TYPE = 4,
    HR_FS_ACCESS = 5,
    HR_FS_BOOTABLE = 6,
    HR_FS_STORAGE_INDEX = 7,
    HR_FS_LAST_FULL_BACKUP_DATE = 8,
    HR_FS_LAST_PARTIAL_BACKUP_DATE = 9
};

static DeviceEntry *get_entry(SubOID *row, size_t row_len,
    enum DeviceType type, int next)
{
    DeviceList *device_list = get_device_list();
    DeviceEntry *entry = NULL;

    if (device_list != NULL) {
        for (int i = 0; i < device_list->len; i++) {
            DeviceEntry *e = device_list->arr[i];
            if (type == 0 || type == e->type) {
                // NOP
            } else if (e->type > type) {
                break;
            } else if (e->type < type) {
                continue;
            }

            if (next) {
                if (row_len < 1 || row[0] < e->id) {
                    entry = e;
                    break;
                }
            } else if (row_len != 1) {
                break;
            } else if (e->id == row[0]) {
                entry = e;
                break;
            }
        }
    }

    return entry;
}

static PartitionEntry *get_partition_entry(SubOID *row, size_t row_len, int next)
{
    if (!next) {
        if (row_len != 2)
            return NULL;

        DeviceStorageEntry *storage =
            (DeviceStorageEntry *) get_entry(row, 1, DEVICE_TYPE_STORAGE, 0);
        if (storage != NULL) {
            for (PartitionEntry *partition = storage->partitions;
                    partition != NULL; partition = partition->next) {
                if (partition->partition_id == row[1]) {
                    return partition;
                }
            }
        }
    } else {
        DeviceList *device_list = get_device_list();
        if (device_list != NULL) {
            for (int i = 0; i < device_list->len; i++) {
                if (device_list->arr[i]->type == DEVICE_TYPE_STORAGE) {
                    DeviceStorageEntry *storage =
                        (DeviceStorageEntry *) device_list->arr[i];
                    if (row_len > 0 && row[0] > storage->device.id) {
                        continue;
                    }
                    for (PartitionEntry *partition = storage->partitions;
                            partition != NULL; partition = partition->next) {
                        if (row_len < 2 || row[0] < storage->device.id
                            || row[1] < partition->partition_id) {
                            return partition;
                        }
                    }
                }
            }
        }
    }

    return NULL;
}

static SnmpErrorStatus get_device_table(SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int column, int next_row)
{
    DeviceEntry *entry = get_entry(row, row_len, 0, next_row);
    CHECK_INSTANCE_FOUND(next_row, entry);

    switch (column) {
        case HR_DEVICE_INDEX: {
            SET_INTEGER_BIND(binding, entry->id);
            break;
        }

        case HR_DEVICE_TYPE: {
            SET_OID_BIND(binding, SNMP_OID_HR_DEVICE, 1, entry->type);
            break;
        }

        case HR_DEVICE_DESCR: {
            SET_OCTET_STRING_RESULT(binding,
                (uint8_t *) strndup(entry->descr, sizeof(entry->descr)),
                strnlen(entry->descr, sizeof(entry->descr)));
            break;
        }

        case HR_DEVICE_ID: {
            SET_OID_BIND(binding, 0, 0);
            break;
        }

        case HR_DEVICE_STATUS: {
            SET_INTEGER_BIND(binding, entry->status);
            break;
        }

        case HR_DEVICE_ERRORS: {
            SET_UNSIGNED_BIND(binding, entry->errors);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_HR_DEVICE,
            HR_DEVICE_TABLE, column, entry->id);
}

static SnmpErrorStatus get_processor_table(SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int column, int next_row)
{
    DeviceProcessorEntry *entry = (DeviceProcessorEntry *) get_entry(row,
            row_len, DEVICE_TYPE_PROCESSOR, next_row);
    CHECK_INSTANCE_FOUND(next_row, entry);

    switch (column) {
        case HR_PROCESSOR_FRW_ID: {
            SET_OID_BIND(binding, 0, 0);
            break;
        }

        case HR_PROCESSOR_LOAD: {
            SET_INTEGER_BIND(binding, entry->load);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_HR_DEVICE,
            HR_PROCESSOR_TABLE, column, entry->device.id);
}

static SnmpErrorStatus get_iface_table(SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int next_row)
{
    DeviceIfaceEntry *entry = (DeviceIfaceEntry *) get_entry(row, row_len,
            DEVICE_TYPE_NETWORK, next_row);
    CHECK_INSTANCE_FOUND(next_row, entry);
    SET_INTEGER_BIND(binding, entry->iface_id);
    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_HR_DEVICE,
        HR_NETWORK_TABLE, HR_NETWORK_IF_INDEX, entry->device.id);
}

static SnmpErrorStatus get_storage_table(SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int column, int next_row)
{
    DeviceStorageEntry *entry = (DeviceStorageEntry *) get_entry(row,
            row_len, DEVICE_TYPE_STORAGE, next_row);
    CHECK_INSTANCE_FOUND(next_row, entry);

    switch (column) {
        case HR_DISK_STORAGE_ACCESS: {
            SET_INTEGER_BIND(binding, entry->access);
            break;
        }

        case HR_DISK_STORAGE_MEDIA: {
            SET_INTEGER_BIND(binding, entry->media);
            break;
        }

        case HR_DISK_STORAGE_REMOVEBLE: {
            SET_INTEGER_BIND(binding, entry->removable);
            break;
        }

        case HR_DISK_STORAGE_CAPACITY: {
            SET_INTEGER_BIND(binding, entry->capacity);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW(next_row, SNMP_OID_HR_DEVICE,
            HR_DISK_STORAGE_TABLE, column, entry->device.id);
}

static SnmpErrorStatus get_partition_table(SubOID *row, size_t row_len,
        SnmpVariableBinding *binding, int column, int next_row)
{
    PartitionEntry *partition = get_partition_entry(row, row_len, next_row);
    CHECK_INSTANCE_FOUND(next_row, partition);

    switch (column) {
        case HR_PARTITION_INDEX: {
            SET_INTEGER_BIND(binding, partition->partition_id);
            break;
        }

        case HR_PARTITION_LABEL: {
            SET_OCTET_STRING_RESULT(binding,
                strndup(partition->label, sizeof(partition->label)),
                strnlen(partition->label, sizeof(partition->label)));
            break;
        }

        case HR_PARTITION_ID: {
            SET_OCTET_STRING_RESULT(binding,
                strndup(partition->uuid, sizeof(partition->uuid)),
                strnlen(partition->uuid, sizeof(partition->uuid)));
            break;
        }

        case HR_PARTITION_SIZE: {
            SET_INTEGER_BIND(binding, partition->size);
            break;
        }

        case HR_PARTITION_FS_INDEX: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }
    }

    INSTANCE_FOUND_INT_ROW2(next_row, SNMP_OID_HR_DEVICE, HR_PARTITION_TABLE,
        column, partition->device_id, partition->partition_id);
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    switch (id) {
        case HR_DEVICE_TABLE: {
            return get_device_table(row, row_len, binding, column, next_row);
        }

        case HR_PROCESSOR_TABLE: {
            return get_processor_table(row, row_len, binding, column, next_row);
        }

        case HR_NETWORK_TABLE: {
            return get_iface_table(row, row_len, binding, next_row);
        }

        case HR_DISK_STORAGE_TABLE: {
            return get_storage_table(row, row_len, binding, column, next_row);
        }

        case HR_PARTITION_TABLE: {
            return get_partition_table(row, row_len, binding, column, next_row);
        }

        default: {
            binding->type = next_row ? SMI_EXCEPT_END_OF_MIB_VIEW :
                SMI_EXCEPT_NO_SUCH_INSTANCE;
            return NO_ERROR;
        }
    }
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *index, size_t index_len,
    SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_hr_device_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, HR_DEVICE_TABLE,
            HR_FS_TABLE - HR_DEVICE_TABLE + 1,
            HR_DEVICE_ERRORS, HR_PROCESSOR_LOAD, HR_NETWORK_IF_INDEX,
            HR_PRINTER_DETECTED_ERROR_STATE, HR_DISK_STORAGE_CAPACITY,
            HR_PARTITION_FS_INDEX, HR_FS_LAST_PARTIAL_BACKUP_DATE)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_HR_DEVICE);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
