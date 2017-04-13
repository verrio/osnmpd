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

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/system/device-cache.h"

#define UPDATE_INTERVAL 8

#define PATH_SYS_BLOCK  "/sys/block"
#define PATH_SYS_BLOCK_SIZE     PATH_SYS_BLOCK"/%s/size"
#define PATH_SYS_BLOCK_RO   PATH_SYS_BLOCK"/%s/ro"
#define PATH_SYS_BLOCK_REMOVABLE    PATH_SYS_BLOCK"/%s/removable"
#define PATH_SYS_BLOCK_PARTITION    PATH_SYS_BLOCK"/%s/partition"
#define PATH_SYS_BLOCK_DEVICE    PATH_SYS_BLOCK"/%s/device"
#define PATH_SYS_BLOCK_STATE    PATH_SYS_BLOCK"/%s/device/state"
#define PATH_SYS_BLOCK_DESCR    PATH_SYS_BLOCK"/%s/device/model"
#define PATH_SYS_BLOCK_SCSI_TYPE    PATH_SYS_BLOCK"/%s/device/type"
#define PATH_SYS_BLOCK_ERASE_SIZE    PATH_SYS_BLOCK"/%s/device/erasesize"

#define PATH_SYS_PARTITION_TEST "%s/%s/partition"
#define PATH_SYS_PARTITION_SIZE "%s/%s/size"
#define PATH_SYS_PARTITION_DEV "%s/%s/dev"
#define PATH_PART_LABEL "/dev/disk/by-partlabel/"
#define PATH_PART_UUID "/dev/disk/by-partuuid/"

#define PATH_SYS_FLASH    "/sys/class/mtd"
#define PATH_SYS_FLASH_TYPE    PATH_SYS_FLASH"/%s/type"
#define PATH_SYS_FLASH_SIZE    PATH_SYS_FLASH"/%s/size"
#define PATH_SYS_FLASH_NAME    PATH_SYS_FLASH"/%s/name"
#define PATH_SYS_FLASH_ALIAS    PATH_SYS_FLASH"/%s/device/modalias"
#define PATH_SYS_FLASH_FAILURES    PATH_SYS_FLASH"/%s/ecc_failures"

#define PATH_SYS_FLASH_PARTITIONS "/sys/class/ubi/"
#define PATH_SYS_FLASH_PART_MTD PATH_SYS_FLASH_PARTITIONS"%s/device/mtd_num"
#define PATH_SYS_FLASH_PART_SIZE PATH_SYS_FLASH_PARTITIONS"%s/data_bytes"
#define PATH_SYS_FLASH_PART_NAME PATH_SYS_FLASH_PARTITIONS"%s/name"

static void *fetch_device_list(void);
static void free_device_list(void *list);
static void add_cpu_entries(DeviceList *);
static void add_network_entries(DeviceList *);
static void add_block_device_entries(DeviceList *);
static void add_block_partition_entries(DeviceStorageEntry *, char *);
static void add_flash_entries(DeviceList *);
static void add_flash_partition_entries(DeviceStorageEntry *);
static void add_entry(DeviceList *, DeviceEntry *);
static char *get_iface_descr(int);
static enum DeviceStorageMedia get_storage_type(uint32_t);
static void find_partition_name(char *, char (*)[64], uint32_t, uint32_t);

DeviceList *get_device_list(void)
{
    return get_mib_cache(fetch_device_list, free_device_list, UPDATE_INTERVAL);
}

static void *fetch_device_list(void)
{
    DeviceList *list = malloc(sizeof(DeviceList));
    if (list == NULL)
        return NULL;
    memset(list, 0, sizeof(DeviceList));

    add_cpu_entries(list);
    add_network_entries(list);
    add_block_device_entries(list);
    add_flash_entries(list);

    return list;
}

static void free_device_list(void *list)
{
    DeviceList *devices = (DeviceList *) list;

    for (int i = 0; i < devices->len; i++) {
        if (devices->arr[i] != NULL
            && devices->arr[i]->type == DEVICE_TYPE_STORAGE) {
            PartitionEntry *partition =
                ((DeviceStorageEntry *) devices->arr[i])->partitions;
            while (partition != NULL) {
                PartitionEntry *next = partition->next;
                free(partition);
                partition = next;
            }
        }
        free(devices->arr[i]);
    }
    free(devices->arr);
    free(devices);
}

static void add_cpu_entries(DeviceList *list)
{
    int count = sysconf(_SC_NPROCESSORS_CONF);
    uint32_t load = 0;

    struct sysinfo s_info;
    if (!sysinfo(&s_info)) {
        load = 100 * s_info.loads[0] / (1 << SI_LOAD_SHIFT);
    }

    for (int i = 0; i < count; i++) {
        DeviceProcessorEntry *entry = malloc(sizeof(DeviceProcessorEntry));
        if (entry) {
            entry->device.id = (i + 1) | DEVICE_ID_PREFIX_CPU;
            entry->device.type = DEVICE_TYPE_PROCESSOR;
            entry->device.status = DEVICE_STATUS_RUNNING;
            entry->device.errors = 0;
            sprintf(entry->device.descr, "Main CPU %i", i);
            entry->load = load;
            add_entry(list, (DeviceEntry *) entry);
        }
    }
}

static void add_network_entries(DeviceList *list)
{
    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd == -1)
        return;

    struct {
        struct nlmsghdr hdr;
        struct ifinfomsg msg;
    } req;
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.msg.ifi_family = AF_UNSPEC;
    if (send(fd, &req, req.hdr.nlmsg_len, 0) < 0)
        goto err;

    int len;
    uint8_t buf[16384];
    struct iovec iov = { buf, sizeof(buf) };
    struct sockaddr_nl sa;
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };

    int done = 0;
    while (!done) {
        if ((len = recvmsg(fd, &msg, 0)) < 0)
            goto err;
        if (len == 0)
            break;

        for (struct nlmsghdr *nh = (struct nlmsghdr *) buf; NLMSG_OK(nh, len);
                nh = NLMSG_NEXT(nh,len)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                done = 1;
                break;
            } else if (nh->nlmsg_type != RTM_NEWLINK) {
                goto err;
            }

            struct ifinfomsg *ifinfo = (struct ifinfomsg *) NLMSG_DATA(nh);
            char *type = get_iface_descr(ifinfo->ifi_type);
            if (type == NULL)
                continue;

            DeviceIfaceEntry *entry = malloc(sizeof(DeviceIfaceEntry));
            if (entry == NULL)
                continue;

            entry->iface_id = ifinfo->ifi_index;
            entry->device.id = ifinfo->ifi_index | DEVICE_ID_PREFIX_NETWORK;
            entry->device.type = DEVICE_TYPE_NETWORK;
            entry->device.status = (ifinfo->ifi_flags & IFF_UP) ?
                    DEVICE_STATUS_RUNNING : DEVICE_STATUS_DOWN;
            entry->device.errors = 0;
            snprintf(entry->device.descr, sizeof(entry->device.descr),
                    "%s network interface (%i)", type, ifinfo->ifi_index);
            add_entry(list, (DeviceEntry *) entry);
        }
    }

err:
    close(fd);
}

static void add_block_device_entries(DeviceList *list)
{
    DIR *dir = opendir(PATH_SYS_BLOCK);
    if (dir == NULL)
        return;

    int i = 0;
    struct dirent *d;
    while ((d = readdir(dir))) {
        char path[1024];

        snprintf(path, sizeof(path), PATH_SYS_BLOCK_PARTITION, d->d_name);
        if (!access(path, F_OK))
            continue;
        snprintf(path, sizeof(path), PATH_SYS_BLOCK_ERASE_SIZE, d->d_name);
        if (!access(path, F_OK))
            continue;
        snprintf(path, sizeof(path), PATH_SYS_BLOCK_DEVICE, d->d_name);
        if (access(path, F_OK))
            continue;

        uint64_t size;
        snprintf(path, sizeof(path), PATH_SYS_BLOCK_SIZE, d->d_name);
        if (read_unsigned64_from_file(path, &size) || size == 0)
            continue;

        uint32_t removable;
        snprintf(path, sizeof(path), PATH_SYS_BLOCK_REMOVABLE, d->d_name);
        if (read_unsigned_from_file(path, &removable))
            continue;

        uint32_t readonly;
        snprintf(path, sizeof(path), PATH_SYS_BLOCK_RO, d->d_name);
        if (read_unsigned_from_file(path, &readonly))
            continue;

        char state[64];
        uint8_t *state_ptr = (uint8_t *) state;
        size_t state_len = sizeof(state);
        snprintf(path, sizeof(path), PATH_SYS_BLOCK_STATE, d->d_name);
        if (read_from_file(path, &state_ptr, &state_len))
            state[0] = '\0';

        char descr[64];
        uint8_t *descr_ptr = (uint8_t *) descr;
        size_t descr_len = sizeof(descr);
        snprintf(path, sizeof(path), PATH_SYS_BLOCK_DESCR, d->d_name);
        if (read_from_file(path, &descr_ptr, &descr_len))
            descr_ptr = (uint8_t *) d->d_name;
        else
            descr[descr_len-1] = '\0';

        uint32_t scsi_type;
        enum DeviceStorageMedia type;
        snprintf(path, sizeof(path), PATH_SYS_BLOCK_SCSI_TYPE, d->d_name);
        if (read_unsigned_from_file(path, &scsi_type)) {
            type = DEVICE_STORAGE_MEDIA_UNKNOWN;
        } else {
            type = get_storage_type(scsi_type);
        }

        DeviceStorageEntry *entry = malloc(sizeof(DeviceStorageEntry));
        if (entry == NULL)
            continue;
        entry->device.id = i++ | DEVICE_ID_PREFIX_STORAGE;
        entry->device.type = DEVICE_TYPE_STORAGE;
        entry->access = readonly ?
            DEVICE_STORAGE_READ_ONLY : DEVICE_STORAGE_READ_WRITE;
        entry->removable = removable ? 1 : 2;
        entry->media = type;
        entry->capacity = size >> 1;
        snprintf(entry->device.descr, sizeof(descr), "Block device (%s)",
                trim_string((char *) descr_ptr));
        entry->device.errors = 0;
        entry->device.status = strncmp(state, "running", 7) ?
            DEVICE_STATUS_UNKNOWN : DEVICE_STATUS_RUNNING;
        entry->partitions = NULL;
        add_entry(list, (DeviceEntry *) entry);

        snprintf(path, sizeof(path), PATH_SYS_BLOCK"/%s", d->d_name);
        add_block_partition_entries(entry, path);
    }

    closedir(dir);
}

static void add_flash_entries(DeviceList *list)
{
    DIR *dir = opendir(PATH_SYS_FLASH);
    if (dir == NULL)
        return;

    struct dirent *d;
    while ((d = readdir(dir))) {
        uint32_t mtd_num;

        if (sscanf(d->d_name, "mtd%"PRIu32, &mtd_num) != 1)
            continue;

        char path[1024];

        uint64_t size;
        snprintf(path, sizeof(path), PATH_SYS_FLASH_SIZE, d->d_name);
        if (read_unsigned64_from_file(path, &size) || size == 0)
            continue;

        uint32_t failures;
        snprintf(path, sizeof(path), PATH_SYS_FLASH_FAILURES, d->d_name);
        if (read_unsigned_from_file(path, &failures))
            continue;

        char descr[64];
        uint8_t *descr_ptr = (uint8_t *) descr;
        size_t descr_len = sizeof(descr);
        snprintf(path, sizeof(path), PATH_SYS_FLASH_ALIAS, d->d_name);
        if (!read_from_file(path, &descr_ptr, &descr_len)) {
            descr[descr_len-1] = '\0';
        } else {
            snprintf(path, sizeof(path), PATH_SYS_FLASH_NAME, d->d_name);
            if (!read_from_file(path, &descr_ptr, &descr_len)) {
                descr[descr_len-1] = '\0';
            } else {
                snprintf(path, sizeof(path), PATH_SYS_FLASH_TYPE, d->d_name);
                if (!read_from_file(path, &descr_ptr, &descr_len)) {
                    descr[descr_len-1] = '\0';
                } else {
                    descr_ptr = (uint8_t *) d->d_name;
                }
            }
        }

        DeviceStorageEntry *entry = malloc(sizeof(DeviceStorageEntry));
        if (entry == NULL)
            continue;
        entry->device.id = mtd_num | 0xC0000 | DEVICE_ID_PREFIX_STORAGE;
        entry->device.type = DEVICE_TYPE_STORAGE;
        entry->access = DEVICE_STORAGE_READ_WRITE;
        entry->removable = 2;
        entry->media = DEVICE_STORAGE_MEDIA_OTHER;
        entry->capacity = size >> 10;
        snprintf(entry->device.descr, sizeof(descr), "Flash device (%s)",
                trim_string((char *) descr_ptr));
        entry->device.errors = failures;
        entry->device.status = DEVICE_STATUS_RUNNING;
        entry->partitions = NULL;
        add_entry(list, (DeviceEntry *) entry);
        add_flash_partition_entries(entry);
    }

    closedir(dir);
}

static void add_entry(DeviceList *list, DeviceEntry *entry)
{
    if (list->len >= list->max_len) {
        size_t new_len = list->max_len ? (list->max_len << 1) : 64;
        DeviceEntry **new_arr = malloc(new_len * sizeof(DeviceEntry *));
        if (new_arr == NULL) {
            return;
        }
        memcpy(new_arr, list->arr, list->max_len * sizeof(DeviceEntry *));
        free(list->arr);
        list->arr = new_arr;
        list->max_len = new_len;
    }

    list->arr[list->len++] = entry;
}

static void add_block_partition_entries(DeviceStorageEntry *storage, char *storage_path)
{
    DIR *dir = opendir(storage_path);
    if (dir == NULL)
        return;

    int i = 0;
    struct dirent *d;
    PartitionEntry *last_entry = NULL;
    while ((d = readdir(dir))) {
        if (d->d_type != DT_DIR)
            continue;

        char path[1024];
        snprintf(path, sizeof(path), PATH_SYS_PARTITION_TEST, storage_path, d->d_name);
        if (access(path, F_OK))
            continue;

        uint64_t size;
        snprintf(path, sizeof(path), PATH_SYS_PARTITION_SIZE, storage_path, d->d_name);
        if (read_unsigned64_from_file(path, &size))
            continue;

        char dev[64];
        uint8_t *dev_ptr = (uint8_t *) dev;
        size_t dev_len = sizeof(dev);
        snprintf(path, sizeof(path), PATH_SYS_PARTITION_DEV, storage_path, d->d_name);
        if (read_from_file(path, &dev_ptr, &dev_len))
            dev[0] = '\0';
        uint32_t major, minor;
        if (sscanf(dev, "%"PRIu32":%"PRIu32"\n", &major, &minor) != 2)
            continue;

        char label[64];
        find_partition_name(PATH_PART_LABEL, &label, major, minor);
        if (strlen(label) == 0)
            snprintf(label, sizeof(label), "no label (%s)", d->d_name);

        char uuid[64];
        find_partition_name(PATH_PART_UUID, &uuid, major, minor);

        PartitionEntry *entry = malloc(sizeof(PartitionEntry));
        if (entry == NULL)
            continue;
        entry->device_id = storage->device.id;
        entry->partition_id = ++i;
        entry->size = size >> 1;
        entry->next = NULL;
        strncpy(entry->label, label, sizeof(label));
        strncpy(entry->uuid, uuid, sizeof(uuid));
        if (last_entry == NULL) {
            storage->partitions = entry;
        } else {
            last_entry->next = entry;
        }
        last_entry = entry;
    }

    closedir(dir);
}

static void add_flash_partition_entries(DeviceStorageEntry *storage)
{
    DIR *dir = opendir(PATH_SYS_FLASH_PARTITIONS);
    if (dir == NULL)
        return;

    int i = 0;
    struct dirent *d;
    PartitionEntry *last_entry = NULL;
    while ((d = readdir(dir))) {
        char path[1024];
        snprintf(path, sizeof(path), PATH_SYS_FLASH_PART_MTD, d->d_name);
        uint32_t mtd_num;
        if (access(path, F_OK)
            || read_unsigned_from_file(path, &mtd_num)
            || mtd_num != (0xffff & storage->device.id)) {
            continue;
        }

        uint64_t size;
        snprintf(path, sizeof(path), PATH_SYS_FLASH_PART_SIZE, d->d_name);
        if (read_unsigned64_from_file(path, &size))
            continue;

        char label[64];
        snprintf(path, sizeof(path), PATH_SYS_FLASH_PART_NAME, d->d_name);
        uint8_t *label_ptr = (uint8_t *) label;
        size_t label_len = sizeof(label);
        if (!read_from_file(path, &label_ptr, &label_len) && label_len > 0) {
            label[label_len-1] = '\0';
        } else {
            label[0] = '\0';
        }

        PartitionEntry *entry = malloc(sizeof(PartitionEntry));
        if (entry == NULL)
            continue;
        entry->device_id = storage->device.id;
        entry->partition_id = ++i;
        entry->size = size >> 10;
        entry->next = NULL;
        strncpy(entry->label, label, sizeof(label));
        strncpy(entry->uuid, d->d_name, sizeof(entry->uuid));
        if (last_entry == NULL) {
            storage->partitions = entry;
        } else {
            last_entry->next = entry;
        }
        last_entry = entry;
    }

    closedir(dir);
}

static void find_partition_name(char *path, char (*buf)[64], uint32_t major, uint32_t minor)
{
    DIR *dir = opendir(path);
    if (dir == NULL) {
        (*buf)[0] = '\0';
        return;
    }

    struct dirent *d;
    while ((d = readdir(dir))) {
        if (d->d_type != DT_LNK)
            continue;

        char block_path[128];
        snprintf(block_path, sizeof(block_path), "%s/%s", path, d->d_name);
        struct stat entry_stat;
        if (stat(block_path, &entry_stat))
            continue;

        if (major(entry_stat.st_rdev) == major && minor(entry_stat.st_rdev) == minor) {
            strncpy((char *) buf, d->d_name, sizeof(*buf));
            goto found;
        }
    }
    (*buf)[0] = '\0';

found:
    closedir(dir);
}

static char *get_iface_descr(int type)
{
    switch (type) {
        case ARPHRD_LOOPBACK:
        case ARPHRD_TUNNEL:
        case ARPHRD_TUNNEL6:
        case ARPHRD_SIT:
        case ARPHRD_IPGRE:
        case ARPHRD_IP6GRE: {
            return NULL;
        }

        case ARPHRD_ETHER:
        case ARPHRD_EETHER:
        case ARPHRD_IEEE802: {
            return "Ethernet";
        }

        case ARPHRD_IEEE80211:
        case ARPHRD_IEEE80211_PRISM:
        case ARPHRD_IEEE80211_RADIOTAP: {
            return "Wi-Fi";
        }

        case ARPHRD_ROSE:
        case ARPHRD_NETROM:
        case ARPHRD_AX25: {
            return "Amateur radio";
        }

        case ARPHRD_SLIP:
        case ARPHRD_CSLIP:
        case ARPHRD_SLIP6:
        case ARPHRD_CSLIP6: {
            return "SLIP modem";
        }

        case ARPHRD_PPP: {
            return "PPP";
        }

        case ARPHRD_HDLC: {
            return "HDLC";
        }

        case ARPHRD_FCPP:
        case ARPHRD_FCAL:
        case ARPHRD_FCPL:
        case ARPHRD_FCFABRIC: {
            return "Fibre Channel";
        }

        case ARPHRD_IEEE802154:
        case ARPHRD_IEEE802154_MONITOR:
        case ARPHRD_6LOWPAN: {
            return "IEEE 802.15.4";
        }

        case ARPHRD_IRDA: {
            return "Infrared";
        }

        default: {
            return "Unidentified";
        }
    }
}

static enum DeviceStorageMedia get_storage_type(uint32_t scsi_type)
{
    switch (scsi_type) {
        case 0x0: {
            return DEVICE_STORAGE_MEDIA_HARD_DISK;
        }

        case 0x5:
        case 0x7:
        case 0x8:
        case 0xf:{
            return DEVICE_STORAGE_MEDIA_OPTICAL_DISK_ROM;
        }

        case 0x1:
        case 0x4:
        case 0x11: {
            return DEVICE_STORAGE_MEDIA_OTHER;
        }

        default: {
            return DEVICE_STORAGE_MEDIA_UNKNOWN;
        }
    }
}
