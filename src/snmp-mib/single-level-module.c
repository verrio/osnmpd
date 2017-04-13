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

#include "snmp-mib/single-level-module.h"

DEF_METHOD(get_var, SnmpErrorStatus, MibModule, SingleLevelMibModule,
        SnmpVariableBinding *binding)
{
    OID *managed_prefix = &this->public.prefix;

    /* should contain at least a sub OID and instance specifier */
    if (binding->oid.len < managed_prefix->len + 2) {
        goto no_such_object;
    }

    int id = binding->oid.subid[managed_prefix->len];

    /* sub ID out of range */
    if (id < this->offset || id > this->limit) {
        goto no_such_object;
    }

    switch (this->leaves[id - this->offset]) {
        case LEAF_SCALAR: {
            if (binding->oid.len != managed_prefix->len + 2
                || binding->oid.subid[binding->oid.len - 1] != 0) {
                goto no_such_object;
            }

            return this->get_scalar(this, id, binding);
        }

        case LEAF_UNUSED: {
            goto no_such_object;
        }

        default: {
            if (this->leaves[id - this->offset] & LEAF_SUBTREE) {
                MibModule *sub_module =
                    &(this->sub_modules[this->leaves[id - this->offset] & 0xff]);
                return sub_module->get_var(sub_module, binding);
            } else {
                /* expects the entry indicator, column and index specifiers */
                if (binding->oid.len < managed_prefix->len + 4 ||
                    binding->oid.subid[managed_prefix->len + 1] != 1) {
                    goto no_such_object;
                }

                int column = binding->oid.subid[managed_prefix->len + 2];
                if (column < 1 || column > this->leaves[id - this->offset]) {
                    goto no_such_object;
                }

                SubOID *row = &binding->oid.subid[managed_prefix->len + 3];
                size_t row_len = binding->oid.len - managed_prefix->len - 3;
                return this->get_tabular(this, id, column, row, row_len, binding, 0);
            }
        }
    }

no_such_object:
    binding->type = SMI_EXCEPT_NO_SUCH_OBJECT;
    return NO_ERROR;
}

DEF_METHOD(get_next_var, SnmpErrorStatus, MibModule, SingleLevelMibModule,
        SnmpVariableBinding *binding)
{
    OID *managed_prefix = &this->public.prefix;

    /* set start of linear traversal */
    int id = this->offset;
    int column = 1;
    SubOID *row = NULL;
    size_t row_len = 0;

    if (binding->oid.len <= managed_prefix->len
            || compare_OID(&binding->oid, managed_prefix) < 0) {
        /* start at beginning of MIB module */
    } else if (binding->oid.subid[managed_prefix->len] > this->limit) {
        goto no_object_available;
    } else if (binding->oid.subid[managed_prefix->len] >= this->offset) {
        if (binding->oid.len < managed_prefix->len + 2) {
            id = binding->oid.subid[managed_prefix->len];
        } else {
            switch (this->leaves[binding->oid.subid[managed_prefix->len] - this->offset]) {
                case LEAF_SCALAR:
                case LEAF_UNUSED: {
                    /* skip object */
                    id = binding->oid.subid[managed_prefix->len] + 1;
                    break;
                }

                default: {
                    id = binding->oid.subid[managed_prefix->len];

                    if (this->leaves[id - this->offset] & LEAF_SUBTREE) {
                        /* start of subtree */
                    } else if (binding->oid.subid[managed_prefix->len + 1] < 1) {
                        /* start of table */
                    } else if (binding->oid.subid[managed_prefix->len + 1] > 1) {
                        /* skip table */
                        id++;
                    } else if (binding->oid.len < managed_prefix->len + 3 ||
                            binding->oid.subid[managed_prefix->len + 2] < 1) {
                        /* start of table */
                    } else if (binding->oid.subid[managed_prefix->len + 2] >
                        this->leaves[id - this->offset]) {
                        /* skip table */
                        id++;
                    } else {
                        column = binding->oid.subid[managed_prefix->len + 2];
                        row = &binding->oid.subid[managed_prefix->len + 3];
                        row_len = binding->oid.len - managed_prefix->len - 3;
                    }
                    break;
                }
            }
        }
    } else {
        /* start at beginning of MIB group */
    }

    /* iterate till first non-null object has been found (tables may be empty) */
    while (id <= this->limit) {
        switch (this->leaves[id - this->offset]) {
            case LEAF_SCALAR: {
                COPY_OID(&binding->oid, &this->public.prefix);
                binding->oid.subid[binding->oid.len] = id;
                binding->oid.subid[binding->oid.len + 1] = 0;
                binding->oid.len += 2;
                return this->get_scalar(this, id, binding);
            }

            case LEAF_UNUSED: {
                column = 1;
                id++;
                break;
            }

            default: {
                if (this->leaves[id - this->offset] & LEAF_SUBTREE) {
                    SnmpErrorStatus status;
                    MibModule *sub_module =
                        &(this->sub_modules[this->leaves[id - this->offset] & 0xff]);
                    int orig_len = binding->oid.len;
                    if (id != binding->oid.subid[managed_prefix->len]) {
                        binding->oid.len = managed_prefix->len + 1;
                    }
                    status = sub_module->get_next_var(sub_module, binding);

                    if (status != NO_ERROR ||
                        binding->type != SMI_EXCEPT_END_OF_MIB_VIEW) {
                        return status;
                    }
                    if (id != binding->oid.subid[managed_prefix->len]) {
                        binding->oid.len = orig_len;
                    }
                    column = 1;
                    id++;
                } else {
                    SnmpErrorStatus status = this->get_tabular(this, id,
                           column, row, row_len, binding, 1);
                    if (status != NO_ERROR ||
                        binding->type != SMI_EXCEPT_END_OF_MIB_VIEW) {
                        return status;
                    } else if (column < this->leaves[id - this->offset]) {
                        column++;
                    } else {
                        column = 1;
                        id++;
                    }
                }
                break;
            }
        }

        row = NULL;
        row_len = 0;
    }

no_object_available:
    binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
    return NO_ERROR;
}

DEF_METHOD(set_var, SnmpErrorStatus, MibModule, SingleLevelMibModule,
        SnmpVariableBinding *binding, int dry_run)
{
    OID *managed_prefix = &this->public.prefix;

    /* should contain at least a sub OID and instance specifier */
    if (binding->oid.len < managed_prefix->len + 2) {
        return NO_CREATION;
    }

    int id = binding->oid.subid[managed_prefix->len];

    /* sub OID out of range */
    if (id < this->offset || id > this->limit) {
        return NO_CREATION;
    }

    switch (this->leaves[id - this->offset]) {
        case LEAF_SCALAR: {
            if (binding->oid.len != managed_prefix->len + 2
                || binding->oid.subid[binding->oid.len - 1] != 0) {
                return NO_CREATION;
            }

            return this->set_scalar(this, id, binding, dry_run);
        }

        case LEAF_UNUSED: {
            return NO_CREATION;
        }

        default: {
            if (this->leaves[id - this->offset] & LEAF_SUBTREE) {
                MibModule *sub_module =
                    &(this->sub_modules[this->leaves[id - this->offset] & 0xff]);
                return sub_module->set_var(sub_module, binding, dry_run);
            } else {
                /* expects the entry indicator, column and index specifiers */
                if (binding->oid.len < managed_prefix->len + 4 ||
                    binding->oid.subid[managed_prefix->len + 1] != 1) {
                    return NO_CREATION;
                }

                int column = binding->oid.subid[managed_prefix->len + 2];
                if (column < 1 || column > this->leaves[id - this->offset]) {
                    return NO_CREATION;
                }

                SubOID *index = &binding->oid.subid[managed_prefix->len + 3];
                size_t index_len = binding->oid.len - managed_prefix->len - 3;
                return this->set_tabular(this, id, column, index, index_len,
                        binding, dry_run);
            }
        }
    }
}

int init_single_level_module(SingleLevelMibModule *module, int offset, int count, ...)
{
    module->offset = offset;
    module->limit = offset + count - 1;
    module->leaves = malloc(sizeof(uint16_t) * count);
    if (module->leaves == NULL) {
        return -1;
    }

    va_list varargs;
    va_start(varargs, count);
    for (int i = 0; i < count; i++) {
        module->leaves[i] = (uint16_t) va_arg(varargs, int);
    }
    va_end(varargs);

    SET_METHOD(module, MibModule, get_var);
    SET_METHOD(module, MibModule, get_next_var);
    SET_METHOD(module, MibModule, set_var);
    return 0;
}

void finish_single_level_module(SingleLevelMibModule *module)
{
    free(module->leaves);
    free(module);
}
