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

#include <stdarg.h>

#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-table-module.h"

DEF_METHOD(get_var, SnmpErrorStatus, MibModule, SingleTableMibModule,
        SnmpVariableBinding *binding)
{
    OID *managed_prefix = &this->public.prefix;

    /* should contain at least an index and instance specifier */
    if (binding->oid.len < managed_prefix->len + 2) {
        goto no_such_object;
    } else if (binding->oid.subid[managed_prefix->len] < this->col_offset) {
        goto no_such_object;
    } else if (binding->oid.subid[managed_prefix->len] > this->col_limit) {
        goto no_such_object;
    }

    int col = binding->oid.subid[managed_prefix->len];
    SubOID *row = &binding->oid.subid[managed_prefix->len + 1];
    size_t row_len = binding->oid.len - managed_prefix->len - 1;
    return this->get_column(this, col, row, row_len, binding, 0);

no_such_object:
    binding->type = SMI_EXCEPT_NO_SUCH_OBJECT;
    return NO_ERROR;
}

DEF_METHOD(get_next_var, SnmpErrorStatus, MibModule, SingleTableMibModule,
        SnmpVariableBinding *binding)
{
    OID *managed_prefix = &this->public.prefix;

    int column = this->col_offset;
    SubOID *row = NULL;
    size_t row_len = 0;

    if (compare_OID(&binding->oid, managed_prefix) < 0
        || binding->oid.len <= managed_prefix->len
        || binding->oid.subid[managed_prefix->len] < this->col_offset) {
        /* start at table top */
    } else if (binding->oid.subid[managed_prefix->len] > this->col_limit) {
        goto no_object_available;
    } else {
        column = binding->oid.subid[managed_prefix->len];
        row = &binding->oid.subid[managed_prefix->len + 1];
        row_len = binding->oid.len - managed_prefix->len - 1;
    }

    /* iterate till first non-null column object has been found */
    while (column <= this->col_limit) {
        SnmpErrorStatus status = this->get_column(this, column, row, row_len, binding, 1);
        if (status != NO_ERROR || binding->type != SMI_EXCEPT_END_OF_MIB_VIEW) {
            return status;
        } else {
            column++;
            row = NULL;
            row_len = 0;
        }
    }

no_object_available:
    binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
    return NO_ERROR;
}

DEF_METHOD(set_var, SnmpErrorStatus, MibModule, SingleTableMibModule,
        SnmpVariableBinding *binding, int dry_run)
{
    OID *managed_prefix = &this->public.prefix;

    /* should contain at least an index and instance specifier */
    if (binding->oid.len < managed_prefix->len + 2) {
        goto no_such_object;
    } else if (binding->oid.subid[managed_prefix->len] < this->col_offset) {
        goto no_such_object;
    } else if (binding->oid.subid[managed_prefix->len] > this->col_limit) {
        goto no_such_object;
    }

    int col = binding->oid.subid[managed_prefix->len];
    SubOID *row = &binding->oid.subid[managed_prefix->len + 1];
    size_t row_len = binding->oid.len - managed_prefix->len - 1;
    return this->set_column(this, col, row, row_len, binding, dry_run);

no_such_object:
    binding->type = SMI_EXCEPT_NO_SUCH_OBJECT;
    return NO_CREATION;
}

int init_single_table_module(SingleTableMibModule *module, int col_offset, int col_limit)
{
    module->col_offset =  col_offset;
    module->col_limit = col_limit;
    SET_METHOD(module, MibModule, get_var);
    SET_METHOD(module, MibModule, get_next_var);
    SET_METHOD(module, MibModule, set_var);
    return 0;
}

void finish_single_table_module(SingleTableMibModule *module)
{
    free(module);
}
