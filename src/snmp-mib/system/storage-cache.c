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
#include <mntent.h>
#include <sys/vfs.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/system/storage-cache.h"

#define UPDATE_INTERVAL 8
#define MOUNTED_FILE_SYSTEMS "/proc/mounts"

static void *fetch_storage_list(void);
static void free_storage_list(void *);

StorageEntry *get_storage_list(void)
{
    return get_mib_cache(fetch_storage_list, free_storage_list, UPDATE_INTERVAL);
}

static void *fetch_storage_list(void)
{
    StorageEntry *head = NULL;
    StorageEntry *tail = NULL;

    FILE *mount_table = setmntent(MOUNTED_FILE_SYSTEMS, "r");
    if (mount_table == NULL) {
        return NULL;
    }

    struct mntent *e;
    int i = 1;
    while ((e = getmntent(mount_table)) != NULL) {
        struct statfs stat;
        if (statfs(e->mnt_dir, &stat) != 0)
            continue;
        if (stat.f_blocks == 0)
            continue;

        StorageEntry *entry = malloc(sizeof(StorageEntry));
        if (entry == NULL)
            goto err;

        entry->index = i++;
        snprintf(entry->descr, sizeof(entry->descr), "%s mounted on %s",
                e->mnt_type, e->mnt_dir);
        entry->allocation_units = stat.f_bsize ? stat.f_bsize : 1;
        entry->size = stat.f_blocks;
        entry->used = stat.f_blocks - stat.f_bfree;
        entry->next = NULL;

        if (head == NULL) {
            head = entry;
            tail = entry;
        } else {
            tail->next = entry;
            tail = entry;
        }
    }
err:
    endmntent(mount_table);
    return head;
}

static void free_storage_list(void *list)
{
    StorageEntry *e = list;

    while (e != NULL) {
        StorageEntry *tmp = e->next;
        free(e);
        e = tmp;
    }
}
