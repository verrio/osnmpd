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

#include <stddef.h>
#include <unistd.h>
#include <stdio.h>

#include "config.h"

#include "snmp-agent/mib-tree.h"
#include "snmp-agent/agent-config.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/single-level-module.h"
#include "snmp-mib/agent/vacm-access-module.h"

/* fixed views */
static const SubOID view_0[] = { 3,97,108,108,1,3,6 };
static const SubOID view_1[] =
    { 9,100,105,115,99,111,118,101,114,121,1,3,6,1,2,1,1 };
static const SubOID *views[] = { view_0, view_1 };
static const size_t views_len[] = { OID_LENGTH(view_0), OID_LENGTH(view_1) };
static const char *view_names[] = { "all", "discovery" };
static const uint8_t masks[] = { 0xe0, 0xfe };

enum VACMViewsObjects {
    VACM_VIEW_SPIN_LOCK = 1,
    VACM_VIEW_FAMILY_TABLE = 2
};

enum VACMViewsTableColumns {
    VACM_VIEW_TREE_FAMILY_VIEW_NAME = 1,
    VACM_VIEW_TREE_FAMILY_SUBTREE = 2,
    VACM_VIEW_TREE_FAMILY_MASK = 3,
    VACM_VIEW_TREE_FAMILY_TYPE = 4,
    VACM_VIEW_TREE_FAMILY_STORAGE_TYPE = 5,
    VACM_VIEW_TREE_FAMILY_STATUS = 6
};

DEF_METHOD(get_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding)
{
    SET_INTEGER_BIND(binding, 0);
    return NO_ERROR;
}

DEF_METHOD(set_scalar, SnmpErrorStatus, SingleLevelMibModule,
        SingleLevelMibModule, int id, SnmpVariableBinding *binding, int dry_run)
{
    return NOT_WRITABLE;
}

DEF_METHOD(get_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *row, size_t row_len,
    SnmpVariableBinding *binding, int next_row)
{
    int view_idx = bsearch_oid_indices(views, views_len,
            sizeof(views_len) / sizeof(size_t), row, row_len, next_row);
    const SubOID *view = view_idx < 0 ? NULL : views[view_idx];
    CHECK_INSTANCE_FOUND(next_row, view);

    switch (column) {
        case VACM_VIEW_TREE_FAMILY_VIEW_NAME: {
            SET_OCTET_STRING_RESULT(binding,
                strdup(view_names[view_idx]), strlen(view_names[view_idx]));
            break;
        }

        case VACM_VIEW_TREE_FAMILY_SUBTREE: {
            binding->type = SMI_TYPE_OID;
            binding->value.oid.len = 0;
            if (fill_row_index_oid(&binding->value.oid, view + view[0] + 1,
                    views_len[view_idx] - view[0] - 1)) {
                return GENERAL_ERROR;
            }
            break;
        }

        case VACM_VIEW_TREE_FAMILY_MASK: {
            uint8_t *mask = malloc(1);
            if (mask == NULL) {
                return GENERAL_ERROR;
            }
            mask[0] = masks[view_idx];
            SET_OCTET_STRING_BIND(binding, mask, 1);
            break;
        }

        case VACM_VIEW_TREE_FAMILY_TYPE: {
            /* included views */
            SET_INTEGER_BIND(binding, 1);
            break;
        }

        case VACM_VIEW_TREE_FAMILY_STORAGE_TYPE: {
            /* readOnly */
            SET_INTEGER_BIND(binding, 5);
            break;
        }

        case VACM_VIEW_TREE_FAMILY_STATUS: {
            /* active */
            SET_INTEGER_BIND(binding, 1);
            break;
        }
    }

    INSTANCE_FOUND_OID_ROW(next_row, SINGLE_PARAM(SNMP_OID_VACM, 1, 5),
        id, column, view, views_len[view_idx]);
}

DEF_METHOD(set_tabular, SnmpErrorStatus, SingleLevelMibModule,
    SingleLevelMibModule, int id, int column, SubOID *index, size_t index_len,
    SnmpVariableBinding *binding, int dry_run)
{
    return NO_CREATION;
}

DEF_METHOD(finish_module, void, MibModule, SingleLevelMibModule)
{
    finish_single_level_module(this);
}

MibModule *init_vacm_views_module(void)
{
    SingleLevelMibModule *module = malloc(sizeof(SingleLevelMibModule));
    if (module == NULL) {
        return NULL;
    } else if (init_single_level_module(module, VACM_VIEW_SPIN_LOCK,
        VACM_VIEW_FAMILY_TABLE - VACM_VIEW_SPIN_LOCK + 1,
        LEAF_SCALAR, VACM_VIEW_TREE_FAMILY_STATUS)) {
        free(module);
        return NULL;
    }

    SET_PREFIX(module, SNMP_OID_VACM, 1, 5);
    SET_OR_ENTRY(module, NULL);
    SET_METHOD(module, MibModule, finish_module);
    SET_METHOD(module, SingleLevelMibModule, get_scalar);
    SET_METHOD(module, SingleLevelMibModule, set_scalar);
    SET_METHOD(module, SingleLevelMibModule, get_tabular);
    SET_METHOD(module, SingleLevelMibModule, set_tabular);
    return &module->public;
}
