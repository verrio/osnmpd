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

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/system/mem-cache.h"

#define UPDATE_INTERVAL 8
#define PATH_MEM_INFO  "/proc/meminfo"
#define MEM_INFO_LINE_BUF   256

static void *fetch_memory_info(void);
static int scan_val(FILE *, char *, uint32_t *);

MemoryInfo *get_memory_info(void)
{
    return get_mib_cache(fetch_memory_info, free, UPDATE_INTERVAL);
}

static void *fetch_memory_info(void)
{
    FILE *f = NULL;
    MemoryInfo *info = malloc(sizeof(MemoryInfo));
    if (info == NULL)
        goto err;
    if ((f = fopen(PATH_MEM_INFO, "r")) == NULL)
        goto err;
    if (scan_val(f, "MemTotal", &info->mem_total))
        goto err;
    if (scan_val(f, "MemFree", &info->mem_free))
        goto err;
    if (scan_val(f, "Buffers", &info->mem_buffers))
        goto err;
    if (scan_val(f, "Cached", &info->mem_cached))
        goto err;
    if (scan_val(f, "SwapTotal", &info->swap_total))
        goto err;
    if (scan_val(f, "SwapFree", &info->swap_free))
        goto err;
    if (scan_val(f, "Shmem", &info->mem_shared))
        goto err;
    info->swap_min = 0;
    fclose(f);
    return info;
err:
    if (f != NULL)
        fclose(f);
    free(info);
    return NULL;
}

static int scan_val(FILE *file, char *prefix, uint32_t *dst)
{
    char line[MEM_INFO_LINE_BUF];

    while (line == fgets(line, sizeof(line), file)) {
        if (strncmp(line, prefix, strlen(prefix)))
            continue;
        line[MEM_INFO_LINE_BUF - 1] = '\0';
        if (sscanf(line + strlen(prefix) + 2, "%"PRIu32, dst) != 1)
            return -1;
        return 0;
    }

    return -1;
}
