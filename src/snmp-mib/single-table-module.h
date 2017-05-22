/*
 * This file is part of the osnmpd distribution (https://github.com/verrio/osnmpd).
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

#ifndef SRC_SNMP_MIB_SINGLE_TABLE_MODULE_H_
#define SRC_SNMP_MIB_SINGLE_TABLE_MODULE_H_

#include "snmp-core/snmp-pdu.h"
#include "snmp-mib/mib-module.h"

/* MIB group consisting of a single tabular object */
typedef struct SingleTableMibModule {

    /* public MIB module methods */
    MibModule public;

    /* private variables */
    int col_offset;
    int col_limit;

    /**
     * @internal
     * get_tabular - fetches the value associated with a cell of the tabular object
     *
     * @param module   IN - this pointer
     * @param column   IN - column to be fetched
     * @param row      IN - row to be fetched
     * @param row_len  IN - length of row identifier
     * @param dst      OUT - destination variable binding
     * @param next_row IN - 0 if given row should be returned,
     * 1 if row following the given row should be returned;  in the latter case,
     * this function should update the OID of the dst variable binding.
     *
     * @return SNMP error code on error, 0 on success
     */
    SnmpErrorStatus (*get_column)(struct SingleTableMibModule *mod, int column,
            SubOID *row, size_t row_len, SnmpVariableBinding *dst, int next_row);

    /**
     * @internal
     * set_tabular - updates/creates a value associated with a cell
     *               of the tabular object
     *
     * @param module  IN - this pointer
     * @param column  IN - column to be updated
     * @param row     IN - row to be updated
     * @param row_len IN - length of row identifier
     * @param src     IN - variable binding containing new value
     * @param dry_run IN - 0 if set action is to be performed,
     *                     1 if set should be validated without executing
     *
     * @return SNMP error code on error, 0 on success
     */
    SnmpErrorStatus (*set_column)(struct SingleTableMibModule *mod, int column,
            SubOID *row, size_t row_len, SnmpVariableBinding *src, int dry_run);

} SingleTableMibModule;

/**
 * init_single_table_module - initialise new single-level module.
 *
 * @param module  OUT - module to be initialised
 * @param offset  IN - column offset
 * @param limit   IN - column limit
 *
 * @return 0 on success or -1 on any error
 */
__attribute__((visibility("default")))
int init_single_table_module(SingleTableMibModule *module, int offset, int limit);

/**
 * finish_single_table_module - finalise a single-level module.
 *
 * @param module  IN - module to be finalised
 */
__attribute__((visibility("default")))
void finish_single_table_module(SingleTableMibModule *module);

#endif /* SRC_SNMP_MIB_SINGLE_TABLE_MODULE_H_ */
