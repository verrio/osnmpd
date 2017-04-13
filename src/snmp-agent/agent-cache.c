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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/sysinfo.h>

#include "snmp-agent/agent-cache.h"
#include "snmp-agent/agent-config.h"
#include "snmp-agent/snmpd.h"
#include "snmp-core/utils.h"

/* file containing the boot counter */
static const char *boot_file = "boot.count";

/* agent boot counter */
static uint32_t boot_count;

/* agent start timestamp */
static uint64_t start_time;

/* agent statistics */
SnmpAgentStatistics agent_statistics;

/* module cache */
SnmpMibModuleCache mib_cache;

int init_cache(void)
{
    int ret = 0;
    char *file_name = NULL;

    /* init non-persistent values */
    memset(&agent_statistics, 0, sizeof(SnmpAgentStatistics));
    memset(&mib_cache, 0, sizeof(SnmpMibModuleCache));
    struct sysinfo s_info;
    if (sysinfo(&s_info)) {
        syslog(LOG_ERR, "failed to determine uptime.");
        start_time = 0;
        ret = -1;
    } else {
        start_time = s_info.uptime;
    }

    /* init persistent values */
    char *cache_dir = get_cache_dir();
    if (cache_dir == NULL) {
        syslog(LOG_CRIT, "missing cache directory");
        goto err;
    }

    if ((file_name = strconcat(cache_dir, boot_file)) == NULL) {
        goto err;
    }

    if (access(file_name, F_OK) != -1) {
        FILE *f = fopen(file_name, "r");
        if (f == NULL) {
            syslog(LOG_WARNING, "boot counter could not be fetched : %s",
                    strerror(errno));
            goto err;
        }
        if (fscanf(f, "%"PRIu32"\n", &boot_count) != 1) {
            syslog(LOG_WARNING, "invalid boot counter file; starting at zero");
            boot_count = 0;
        }
        fclose(f);

        boot_count++;
    } else {
        syslog(LOG_WARNING, "no boot counter found.  starting at zero.");
        boot_count = 0;
    }

    FILE *f = fopen(file_name, "w");
    if (f == NULL) {
        syslog(LOG_WARNING, "boot counter could not be updated : %s",
                strerror(errno));
        goto err;
    }
    fprintf(f, "%"PRIu32"\n", boot_count);
    fflush(f);
    fclose(f);

    return ret;
err:
    if (file_name) {
        free(file_name);
    }
    boot_count = 0;
    return -1;
}

int finish_cache(void)
{
    if (mib_cache.free_val != NULL && mib_cache.val != NULL) {
        mib_cache.free_val(mib_cache.val);
        mib_cache.val = NULL;
    }

    return 0;
}

uint32_t get_boot_count(void)
{
    return boot_count;
}

int reset_boot_count(void)
{
    boot_count = 0;

    char *cache_dir = get_cache_dir();
    if (cache_dir == NULL) {
        syslog(LOG_CRIT, "missing cache directory");
        return -1;
    }
    char *file_name = strconcat(cache_dir, boot_file);
    if (file_name == NULL) {
        return -1;
    }

    FILE *f = fopen(file_name, "w");
    if (f == NULL) {
        syslog(LOG_WARNING, "boot counter could not be cleared : %s",
                strerror(errno));
        return -1;
    }
    fprintf(f, "%"PRIu32"\n", boot_count);
    fflush(f);
    fclose(f);

    return 0;
}

uint64_t get_start_time(void)
{
    return start_time;
}

uint32_t get_uptime(void)
{
    struct sysinfo s_info;
    if (sysinfo(&s_info)) {
        syslog(LOG_WARNING, "failed to determine system uptime.");
        return -1;
    } else {
        return (uint32_t) (s_info.uptime - start_time);
    }
}

uint32_t rebase_duration(uint32_t duration)
{
    uint32_t uptime = get_uptime();

    if (uptime == -1 || uptime < duration) {
        return 0;
    }

    return uptime - duration;
}

SnmpAgentStatistics *get_statistics(void)
{
    return &agent_statistics;
}

void *get_mib_cache(void *(*fetch_cache)(void), void (*free_cache)(void *),
        uint32_t max_age)
{
    struct sysinfo s_info;
    if (sysinfo(&s_info)) {
        return NULL;
    }

    if (mib_cache.update_val != fetch_cache ||
        (uint32_t) s_info.uptime - mib_cache.last_update > max_age) {
        if (mib_cache.free_val != NULL && mib_cache.val != NULL) {
            mib_cache.free_val(mib_cache.val);
        }

        mib_cache.last_update = (uint32_t) s_info.uptime;
        mib_cache.update_val = fetch_cache;
        mib_cache.free_val = free_cache;
        mib_cache.val = fetch_cache();
    }

    return mib_cache.val;
}
