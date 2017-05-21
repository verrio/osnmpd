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

#ifndef SRC_SNMP_MIB_SYSTEM_CPU_CACHE_H_
#define SRC_SNMP_MIB_SYSTEM_CPU_CACHE_H_

typedef struct {

    /* average amount of memory swapped in */
    uint32_t swap_in;

    /* average amount of memory swapped out */
    uint32_t swap_out;

    /* average amount of data written to external I/O device */
    uint32_t io_sent;

    /* average amount of data read from external I/O device */
    uint32_t io_received;

    /* average rate of interrupts processed */
    uint32_t interrupts;

    /* average rate of context switches */
    uint32_t context_switch;

    /* CPU time spent in user-level code */
    uint32_t cpu_user;

    /* CPU time spent in system-level code */
    uint32_t cpu_system;

    /* CPU idle time */
    uint32_t cpu_idle;

} CpuInfo;

/**
 * @internal
 * get_cpu_info - returns CPU statistics
 *
 * @return CPU statistics, or NULL if not available.
 */
CpuInfo *get_cpu_info(void);

#endif /* SRC_SNMP_MIB_SYSTEM_CPU_CACHE_H_ */
