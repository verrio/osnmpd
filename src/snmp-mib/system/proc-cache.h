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

#ifndef SRC_SNMP_MIB_SYSTEM_PROC_CACHE_H_
#define SRC_SNMP_MIB_SYSTEM_PROC_CACHE_H_

#define LINUX_PROC "/proc"
#define LINUX_PROC_CMDLINE "/proc/%d/cmdline"
#define LINUX_PROC_EXE "/proc/%d/exe"
#define LINUX_PROC_STAT "/proc/%d/stat"
#define LINUX_PROC_STATM "/proc/%d/statm"

typedef struct {
    size_t len;
    uint32_t *arr;
} PIDList;

/**
 * @internal
 * get_pid_list - returns list of running processes
 *
 * @return list of processes, or NULL if not available.
 */
PIDList *get_pid_list(void);

/**
 * @internal
 * pid_exists - checks if given process identifier exists
 *
 * @param pid IN - process identifier to be validated.
 *
 * @return 0 if pid exists, -1 otherwise.
 */
int pid_exists(uint32_t pid);

/**
 * @internal
 * get_next_pid - returns the smallest pid following the given process identifier
 *
 * @param prev IN - preceding process identifier
 *
 * @return following process identifier, or -1 if no match found.
 */
uint32_t get_next_pid(uint32_t prev);

#endif /* SRC_SNMP_MIB_SYSTEM_PROC_CACHE_H_ */
