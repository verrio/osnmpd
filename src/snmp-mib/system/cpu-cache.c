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
#include <time.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-core/utils.h"
#include "snmp-mib/mib-utils.h"
#include "snmp-mib/system/cpu-cache.h"

#define UPDATE_INTERVAL 60
#define PATH_STAT  "/proc/stat"
#define PATH_VMSTAT "/proc/vmstat"
#define LINE_BUF   256

static int update_cpu_info(uint32_t interval);
static int scan_val(FILE *, char *, uint64_t *);

/* previous counters */
static uint64_t prev_time = 0;
static uint64_t prev_usr = 0;
static uint64_t prev_sys = 0;
static uint64_t prev_idle = 0;
static uint64_t prev_total = 0;
static uint64_t prev_ctxt = 0;
static uint64_t prev_intr = 0;
static uint64_t prev_swapin = 0;
static uint64_t prev_swapout = 0;
static uint64_t prev_pagein = 0;
static uint64_t prev_pageout = 0;
static CpuInfo cpu_info;

CpuInfo *get_cpu_info(void)
{
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time))
        return NULL;

    uint32_t interval = time.tv_sec - prev_time;
    if (prev_time == 0 || interval > UPDATE_INTERVAL) {
        if (update_cpu_info(interval))
            return NULL;
        prev_time = time.tv_sec;
    }

    if (prev_time == 0)
        return NULL;
    return &cpu_info;
}

static int update_cpu_info(uint32_t interval)
{
    FILE *f = NULL;

    uint32_t hertz = sysconf(_SC_CLK_TCK);
    if (hertz == -1)
        goto err;

    if ((f = fopen(PATH_STAT, "r")) == NULL)
        goto err;
    char line[LINE_BUF];
    if (line != fgets(line, sizeof(line), f))
        goto err;
    line[LINE_BUF - 1] = '\0';
    uint64_t user, nice, system, idle, iowait, irq, softirq;
    if (sscanf(line, "cpu  %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64
        " %"PRIu64" %"PRIu64" %"PRIu64, &user, &nice,
        &system, &idle, &iowait, &irq, &softirq) != 7)
        goto err;

    uint64_t ctxt, intr;
    if (scan_val(f, "intr", &intr))
        goto err;
    if (scan_val(f, "ctxt", &ctxt))
        goto err;
    fclose(f);

    uint64_t swapin, swapout, pagein, pageout;
    if ((f = fopen(PATH_VMSTAT, "r")) == NULL)
        goto err;
    if (scan_val(f, "pgpgin", &pagein))
        goto err;
    if (scan_val(f, "pgpgout", &pageout))
        goto err;
    if (scan_val(f, "pswpin", &swapin))
        goto err;
    if (scan_val(f, "pswpout", &swapout))
        goto err;
    fclose(f);

    uint64_t total = user + nice + system + idle + iowait + irq + softirq;
    cpu_info.cpu_user = (total - prev_total) ?
            100 * (user + nice - prev_usr) / (total - prev_total) : 0;
    cpu_info.cpu_system = (total - prev_total) ?
            100 * (system - prev_sys) / (total - prev_total) : 0;
    cpu_info.cpu_idle = (total - prev_total) ?
            100 * (idle - prev_idle) / (total - prev_total) : 0;
    cpu_info.context_switch = (ctxt  - prev_ctxt) / interval;
    cpu_info.interrupts = (intr  - prev_intr) / interval;
    cpu_info.io_received = (pagein - prev_pagein) / interval;
    cpu_info.io_sent = (pageout - prev_pageout) / interval;
    cpu_info.swap_in = (swapin - prev_swapin) / interval;
    cpu_info.swap_out = (swapout - prev_swapout) / interval;

    prev_usr = user + nice;
    prev_sys = system;
    prev_idle = idle;
    prev_total = total;
    prev_ctxt = ctxt;
    prev_intr = intr;
    prev_swapin = swapin;
    prev_swapout = swapout;
    prev_pagein = pagein;
    prev_pageout = pageout;
    return 0;
err:
    if (f != NULL)
        fclose(f);
    return -1;
}

static int scan_val(FILE *file, char *prefix, uint64_t *dst)
{
    char line[LINE_BUF];

    while (line == fgets(line, sizeof(line), file)) {
        if (strncmp(line, prefix, strlen(prefix)))
            continue;
        line[LINE_BUF - 1] = '\0';
        if (sscanf(line + strlen(prefix) + 1, "%"PRIu64, dst) != 1)
            return -1;
        return 0;
    }

    return -1;
}
