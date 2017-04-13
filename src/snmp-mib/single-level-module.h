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

#ifndef SRC_SNMP_MIB_SINGLE_LEVEL_MODULE_H_
#define SRC_SNMP_MIB_SINGLE_LEVEL_MODULE_H_

#include <stddef.h>

#include "snmp-core/snmp-pdu.h"
#include "snmp-mib/mib-module.h"
#include "snmp-mib/mib-utils.h"

#define SET_SUBMODULE(module, entry) do { \
    ((SingleLevelMibModule *) module)->sub_modules = entry; \
} while (0);

#define EMPTY_TABLE(next_row, binding) do { \
    (binding)->type = next_row ? SMI_EXCEPT_END_OF_MIB_VIEW : \
            SMI_EXCEPT_NO_SUCH_INSTANCE; \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_INT_ROW(next_row, prefix, table_id, column, row_id) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, table_id, 1, column, row_id); \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_INT_ROW2(next_row, prefix, table_id, column, \
        row_id1, row_id2) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, table_id, 1, column, row_id1, row_id2); \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_OID_ROW(next_row, prefix, table_id, column, \
    oid_indx, oid_indx_len) do {\
    if ((next_row)) { \
        SET_OID((binding)->oid, prefix, (table_id), 1, (column)); \
        if (fill_row_index_oid(&((binding)->oid), (oid_indx), (oid_indx_len))) { \
            return GENERAL_ERROR; \
        } \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_OCTET_STRING_ROW(next_row, prefix, table_id, column, \
    row_indx, row_indx_len) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, (table_id), 1, (column)); \
        if (fill_row_index_string(&((binding)->oid), row_indx, row_indx_len)) { \
            return GENERAL_ERROR; \
        } \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_OCTET_STRING_ROW2(next_row, prefix, table_id, column, \
    row_indx1, row_indx1_len, row_indx2, row_indx2_len) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, table_id, 1, column); \
        if (fill_row_index_string(&((binding)->oid), row_indx1, row_indx1_len)) { \
            return GENERAL_ERROR; \
        } else if (fill_row_index_string(&((binding)->oid), row_indx2, row_indx2_len)) { \
            return GENERAL_ERROR; \
        } \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_INT_OCTET_STRING_ROW(next_row, prefix, table_id, column, \
    row_indx1, row_indx2, row_indx2_len) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, table_id, 1, column, row_indx1); \
        if (fill_row_index_string(&((binding)->oid), row_indx2, row_indx2_len)) { \
            return GENERAL_ERROR; \
        } \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_INT_OCTET_STRING_INT_ROW(next_row, prefix, table_id, column, \
    row_indx1, row_indx2, row_indx2_len, row_indx3) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, table_id, 1, column, row_indx1); \
        if (fill_row_index_string(&((binding)->oid), row_indx2, row_indx2_len)) { \
            return GENERAL_ERROR; \
        } else if ((binding)->oid.len + 1 >= MAX_OID_LEN) { \
            return GENERAL_ERROR; \
        } \
        (binding)->oid.subid[(binding)->oid.len++] = row_indx3; \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_INT2_OCTET_STRING_ROW(next_row, prefix, table_id, column, \
    row_indx1, row_indx2, row_indx3, row_indx3_len) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, table_id, 1, column, row_indx1, row_indx2); \
        if (fill_row_index_string(&((binding)->oid), row_indx3, row_indx3_len)) { \
            return GENERAL_ERROR; \
        } \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_INT_FIXED_STRING_ROW(next_row, prefix, table_id, column, \
    row_indx1, row_indx2, row_indx2_len) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, (table_id), 1, (column), (row_indx1)); \
        if (fill_row_index_fixed_string(&((binding)->oid), row_indx2, row_indx2_len)) { \
            return GENERAL_ERROR; \
        } \
    } \
    return NO_ERROR; \
} while (0);

#define INSTANCE_FOUND_FIXED_STRING_ROW(next_row, prefix, table_id, column, \
    row_indx, row_indx_len) do {\
    if ((next_row)) { \
        SET_OID(binding->oid, prefix, (table_id), 1, (column)); \
        if (fill_row_index_fixed_string(&((binding)->oid), row_indx, row_indx_len)) { \
            return GENERAL_ERROR; \
        } \
    } \
    return NO_ERROR; \
} while (0);

#define CHECK_INT_FOUND(next_row, instance) do { \
    if ((instance) == -1) { \
        binding->type = (next_row) ? SMI_EXCEPT_END_OF_MIB_VIEW : \
                SMI_EXCEPT_NO_SUCH_INSTANCE; \
        return NO_ERROR; \
    } \
} while (0);

#define CHECK_INSTANCE_FOUND(next_row, instance) do { \
    if ((instance) == NULL) { \
        binding->type = (next_row) ? SMI_EXCEPT_END_OF_MIB_VIEW : \
                SMI_EXCEPT_NO_SUCH_INSTANCE; \
        return NO_ERROR; \
    } \
} while (0);

#define CHECK_UTF8_STRING(binding, min_len, max_len) do { \
    if ((binding)->type != SMI_TYPE_OCTET_STRING) { \
        return WRONG_TYPE; \
    } else if ((binding)->value.octet_string.len < min_len \
        || (binding)->value.octet_string.len > max_len) { \
        return WRONG_LENGTH; \
    } else if (is_utf8((binding)->value.octet_string.octets, \
            (binding)->value.octet_string.len)) { \
        return WRONG_ENCODING; \
    } \
} while (0);

#define SET_OCTET_STRING_RESULT(binding, val, val_len) do { \
    uint8_t *res = (uint8_t *) (val); \
    if ((res) == NULL) { \
        return GENERAL_ERROR; \
    } \
    SET_OCTET_STRING_BIND(binding, res, val_len); \
} while (0);

#define SET_OPAQUE_RESULT(binding, val, val_len) do { \
    uint8_t *res = (uint8_t *) (val); \
    if ((res) == NULL) { \
        return GENERAL_ERROR; \
    } \
    SET_OPAQUE_BIND(binding, res, val_len); \
} while (0);

/* object types present at this level */
#define LEAF_SCALAR 0x0
#define LEAF_SUBTREE 0xf000
#define LEAF_UNUSED 0xffff

/* MIB group consisting of a consecutive single-level
 * range of scalar and table objects. */
typedef struct SingleLevelMibModule {

    /* public MIB module methods */
    MibModule public;

    /* private variables */
    int offset;
    int limit;
    uint16_t *leaves;
    MibModule *sub_modules;

    /**
     * @internal
     * get_scalar - fetches the value associated with a leaf object
     *
     * @param module  IN - this pointer
     * @param id      IN - leaf identifier
     * @param dst     OUT - destination variable binding
     *
     * @return SNMP error code on error, 0 on success
     */
    SnmpErrorStatus (*get_scalar)(struct SingleLevelMibModule *mod, int id,
            SnmpVariableBinding *dst);

    /**
     * @internal
     * set_scalar - updates the value associated with a leaf object
     *
     * @param module  IN - this pointer
     * @param id      IN - leaf identifier
     * @param src     IN - variable binding containing new value
     * @param dry_run IN - 0 if set action is to be performed,
     *                     1 if set should be validated without executing
     *
     * @return resulting SNMP error code of set action
     */
    SnmpErrorStatus (*set_scalar)(struct SingleLevelMibModule *mod, int id,
            SnmpVariableBinding *src, int dry_run);

    /**
     * @internal
     * get_tabular - fetches the value associated with a cell of a tabular object
     *
     * @param module   IN - this pointer
     * @param id       IN - table identifier
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
    SnmpErrorStatus (*get_tabular)(struct SingleLevelMibModule *mod, int id, int column,
            SubOID *row, size_t row_len, SnmpVariableBinding *dst, int next_row);

    /**
     * @internal
     * set_tabular - updates/creates a value associated with a cell
     *               of a tabular object
     *
     * @param module  IN - this pointer
     * @param id      IN - table identifier
     * @param column  IN - column to be updated
     * @param row     IN - row to be updated
     * @param row_len IN - length of row identifier
     * @param src     IN - variable binding containing new value
     * @param dry_run IN - 0 if set action is to be performed,
     *                     1 if set should be validated without executing
     *
     * @return SNMP error code on error, 0 on success
     */
    SnmpErrorStatus (*set_tabular)(struct SingleLevelMibModule *mod, int id, int column,
            SubOID *row, size_t row_len, SnmpVariableBinding *src, int dry_run);

} SingleLevelMibModule;

/**
 * @internal
 * init_single_level_module - initialise new single-level module.
 *
 * @param module  OUT - module to be initialized
 * @param offset  IN - leaf offset
 * @param count   IN - amount of leaves
 * @param varargs IN - amount of columns for each leaf
 *
 * @return 0 on success or -1 on any error
 */
int init_single_level_module(SingleLevelMibModule *module, int offset, int count, ...);

/**
 * @internal
 * finish_single_level_module - finalise a single-level module.
 *
 * @param module  IN - module to be finalised
 */
void finish_single_level_module(SingleLevelMibModule *module);

#endif /* SRC_SNMP_MIB_SINGLE_LEVEL_MODULE_H_ */
