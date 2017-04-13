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
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <dirent.h>
#include <utmpx.h>
#include <time.h>
#include <linux/rtc.h>

#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-core/snmp-date-time.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/system/hr-system-module.h"

#define RTC_FILE "/dev/rtc"
#define LINUX_PROC "/proc"
#define LINUX_ARGS "/proc/cmdline"
#define PID_MAX "/proc/sys/kernel/pid_max"

#define HR_COMPLIANCE_OID   SNMP_OID_MIB2,25,7,2,1

static SysOREntry host_res_or_entry = {
    .or_id = {
        .subid = { HR_COMPLIANCE_OID },
        .len = OID_SEQ_LENGTH(HR_COMPLIANCE_OID)
    },
    .or_descr = "HOST-RESOURCES-MIB - host system resources",
    .next = NULL
};

enum HRSystemObjects {
    HR_SYSTEM_UPTIME = 1,
    HR_SYSTEM_DATE = 2,
    HR_SYSTEM_INITIAL_LOAD_DEVICE = 3,
    HR_SYSTEM_INITIAL_LOAD_PARAMETERS = 4,
    HR_SYSTEM_NUM_USERS = 5,
    HR_SYSTEM_PROCESSES = 6,
    HR_SYSTEM_MAX_PROCESSES = 7
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    switch (id) {
        case HR_SYSTEM_UPTIME: {
            struct sysinfo s_info;
            if (sysinfo(&s_info)) {
                return INCONSISTENT_VALUE;
            }

            SET_TIME_TICKS_BIND(binding, s_info.uptime * 100);
            break;
        }

        case HR_SYSTEM_DATE: {
            struct timespec system_time;
            if (clock_gettime(CLOCK_REALTIME, &system_time) == -1) {
                return INCONSISTENT_VALUE;
            } else if (encode_date_time(system_time.tv_sec * 1000 +
                system_time.tv_nsec / 1000000, binding)) {
                return GENERAL_ERROR;
            }
            break;
        }

        case HR_SYSTEM_INITIAL_LOAD_DEVICE: {
            SET_INTEGER_BIND(binding, 0);
            break;
        }

        case HR_SYSTEM_INITIAL_LOAD_PARAMETERS: {
            uint8_t buf[1024];
            uint8_t *buf_ptr = buf;
            size_t buf_len = sizeof(buf);

            if (read_from_file(LINUX_ARGS, &buf_ptr, &buf_len)) {
                return GENERAL_ERROR;
            } else if (buf_len > 0) {
                buf_len--;
            }

            SET_OCTET_STRING_RESULT(binding, memdup(buf, buf_len), buf_len);
            break;
        }

        case HR_SYSTEM_NUM_USERS: {
            struct utmpx *tmp;
            uint32_t users = 0;
            setutxent();
            while ((tmp = getutxent()) != NULL) {
                if (tmp->ut_type == USER_PROCESS) {
                    users++;
                }
            }
            endutxent();
            SET_GAUGE_BIND(binding, users);
            break;
        }

        case HR_SYSTEM_PROCESSES: {
            uint32_t processes = 0;

            DIR *dir = opendir(LINUX_PROC);
            if (dir == NULL) {
                return GENERAL_ERROR;
            }

            struct dirent *entry;
            while((entry = readdir(dir)) != NULL) {
                if (isdigit(entry->d_name[0])) {
                    processes++;
                }
            }

            closedir(dir);
            SET_GAUGE_BIND(binding, processes);
            break;
        }

        case HR_SYSTEM_MAX_PROCESSES: {
            if (read_unsigned_from_file(PID_MAX, &binding->value.unsigned_integer)) {
                return GENERAL_ERROR;
            }
            binding->type = SMI_TYPE_INTEGER_32;
            break;
        }
    }

    return NO_ERROR;
}

DEF_METHOD(set_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding, int dry_run)
{
    switch (id) {
        case HR_SYSTEM_DATE: {
            uint64_t timestamp;
            if (decode_timestamp(&timestamp, binding)) {
                return WRONG_ENCODING;
            }

            if (!dry_run) {
                struct timespec new_time;
                new_time.tv_sec = timestamp / 1000;
                new_time.tv_nsec = timestamp % 1000 * 1000000;
                if (clock_settime(CLOCK_REALTIME, &new_time) == -1) {
                    return COMMIT_FAILED;
                }

                if (access(RTC_FILE, F_OK) != -1) {
                    /* assume UTC on RTC */
                    struct tm rt;
                    if (gmtime_r(&new_time.tv_sec, &rt) == NULL) {
                        return COMMIT_FAILED;
                    }
                    rt.tm_isdst = 0;

                    int rtc = open(RTC_FILE, O_RDONLY);
                    if (rtc == -1) {
                        return COMMIT_FAILED;
                    }

                    int ret = ioctl(rtc, RTC_SET_TIME, &rt);
                    close(rtc);

                    if (ret == -1) {
                        return COMMIT_FAILED;
                    }
                }
            }

            return NO_ERROR;
        }

        default: {
            return NOT_WRITABLE;
        }
    }
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_hr_system_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, HR_SYSTEM_UPTIME,
            HR_SYSTEM_MAX_PROCESSES - HR_SYSTEM_UPTIME + 1, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR,
            LEAF_SCALAR, LEAF_SCALAR, LEAF_SCALAR)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_HR_SYSTEM);
    SET_OR_ENTRY(module, &host_res_or_entry);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    return &module->public;
}
