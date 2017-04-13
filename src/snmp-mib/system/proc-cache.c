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
#include <ctype.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/system/proc-cache.h"

#define UPDATE_INTERVAL 4

static void *fetch_pid_list(void);
static void free_pid_list(void *);
static int pid_cmp(const void *, const void *);

int pid_exists(const uint32_t pid)
{
    char buf[64];
    snprintf(buf, sizeof(buf), LINUX_PROC"/%"PRIu32, pid);
    return access(buf, F_OK) == -1 ? -1 : 0;
}

uint32_t get_next_pid(const uint32_t prev)
{
    PIDList *list = get_pid_list();

    if (list == NULL) {
        return -1;
    }

    int index = bsearch_next(&prev, list->arr, list->len, sizeof(uint32_t), pid_cmp);
    if (index == -1) {
        return -1;
    }
    return list->arr[index];
}

PIDList *get_pid_list(void)
{
    return get_mib_cache(fetch_pid_list, free_pid_list, UPDATE_INTERVAL);
}

static void *fetch_pid_list(void)
{
    PIDList *list = malloc(sizeof(PIDList));
    if (list == NULL) {
        return NULL;
    }

    list->len = 0;
    list->arr = NULL;

    DIR *dir = opendir(LINUX_PROC);
    if (dir == NULL) {
        goto err;
    }

    int i = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) {
            continue;
        }

        if (i >= list->len) {
            size_t new_len = list->len < 255 ? 255 : (list->len << 1);
            uint32_t *tmp = malloc(new_len * sizeof(uint32_t));
            if (tmp == NULL) {
                goto err;
            }

            memcpy(tmp, list->arr, list->len * sizeof(uint32_t));
            free(list->arr);
            list->arr = tmp;
            list->len = new_len;
        }

        list->arr[i++] = strtol(entry->d_name, (char **)NULL, 10);
    }
    list->len = i;
    qsort(list->arr, list->len, sizeof(uint32_t), pid_cmp);
err:
    closedir(dir);
    return list;
}

static void free_pid_list(void *list)
{
    free(((PIDList *) list)->arr);
    free(list);
}

static int pid_cmp(const void *pid1, const void *pid2)
{
    if (*(uint32_t *) pid1 > *(uint32_t *) pid2) {
        return 1;
    } else if (*(uint32_t *) pid1 < *(uint32_t *) pid2) {
        return -1;
    } else {
        return 0;
    }
}
