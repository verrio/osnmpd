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

#include <syslog.h>
#include <stdio.h>

#include "snmp-agent/mib-tree.h"
#include "snmp-core/utils.h"
#include "snmp-core/snmp-types.h"
#include "snmp-mib/mib-module.h"

#define UPDATE_HEIGHT(x) \
    x->height = 1 + max(get_left_height(x), get_right_height(x))

/* MIB subtree */
typedef struct MibTreeNode {
    int height;
    MibModule *module;
    struct MibTreeNode *left_child;
    struct MibTreeNode *right_child;
} MibTreeNode;

/* MIB tree root */
static MibTreeNode *root_node;

static void add_or_entry(SysOREntry *new_entry);
static MibModule *find_module(OID *o);
static SnmpErrorStatus find_next_var(SnmpVariableBinding *, MibTreeNode *);
static MibTreeNode *add_module_to_subtree(MibTreeNode *, MibTreeNode *);
static MibTreeNode *balance_tree(MibTreeNode *);
static int get_left_height(const MibTreeNode *);
static int get_right_height(const MibTreeNode *);
static void free_tree(MibTreeNode *);
#ifdef DEBUG
static void dump_mib_subtree(const MibTreeNode *, uint8_t *, int, uint8_t[]);
#endif

/* MIB registered OR entries */
static SysOREntry *or_entries = NULL;

/* MIB registerd application modules */
static MibApplicationModule *app_modules = NULL;

int init_mib_tree(void)
{
    /* NOP */
    return 0;
}

int finish_mib_tree(void)
{
    free_tree(root_node);
    root_node = NULL;
    return 0;
}

int add_module(MibModule *(*module_gen)(void), char *mod_name)
{
    MibModule *module = module_gen();
    if (module == NULL) {
        syslog(LOG_ERR, "failed to initialise module '%s'", mod_name);
        return -1;
    }

    MibTreeNode *node = malloc(sizeof(MibTreeNode));
    if (node == NULL) {
        return -1;
    }

    node->height = 1;
    node->module = module;
    node->left_child = NULL;
    node->right_child = NULL;

    if (root_node == NULL) {
        root_node = node;
    } else {
        MibTreeNode *new_root = add_module_to_subtree(node, root_node);
        if (new_root == NULL) {
            free(node);
            return -1;
        }

        root_node = new_root;
    }

    syslog(LOG_DEBUG, "loaded module %s", mod_name);

    add_or_entry(module->or_entry);
    return 0;
}

int add_app_module(MibApplicationModule *app_module)
{
    if (app_module == NULL) {
        return -1;
    }

    if (app_modules == NULL) {
        app_modules = app_module;
    } else {
        MibApplicationModule *tail = app_modules;
        while (tail->next != NULL) {
            tail = tail->next;
        }
        tail->next = app_module;
    }
    return 0;
}

MibApplicationModule *mib_get_app_modules(void)
{
    return app_modules;
}

static void add_or_entry(SysOREntry *new_entry)
{
    if (new_entry == NULL) {
        return;
    }

    if (or_entries == NULL) {
        or_entries = new_entry;
    } else {
        SysOREntry *tail = or_entries;
        while (tail->next != NULL) {
            tail = tail->next;
        }
        tail->next = new_entry;
    }
}

SysOREntry *mib_get_or_entries(void)
{
    return or_entries;
}

SnmpErrorStatus mib_get_entry(SnmpVariableBinding *binding)
{
    MibModule *module = find_module(&binding->oid);

    if (module == NULL) {
        binding->type = SMI_EXCEPT_NO_SUCH_OBJECT;
        return NO_ERROR;
    }

    return module->get_var(module, binding);
}

SnmpErrorStatus mib_get_next_entry(SnmpVariableBinding *binding)
{
    return find_next_var(binding, root_node);
}

SnmpErrorStatus mib_set_entry(SnmpVariableBinding *binding, int dry_run)
{
    MibModule *module = find_module(&binding->oid);

    if (module == NULL) {
        return NOT_WRITABLE;
    }

    return module->set_var(module, binding, dry_run);
}

static MibModule *find_module(OID *o)
{
    MibTreeNode *current = root_node;

    while (current != NULL) {
        int cmp = prefix_compare_OID(&current->module->prefix, o);

        if (cmp == 0) {
            return current->module;
        } else if (cmp < 0) {
            current = current->right_child;
        } else {
            current = current->left_child;
        }
    }

    return NULL;
}

static SnmpErrorStatus find_next_var(SnmpVariableBinding *binding, MibTreeNode *current)
{
    if (current == NULL) {
        binding->type = SMI_EXCEPT_END_OF_MIB_VIEW;
        return NO_ERROR;
    }

    int cmp = prefix_compare_OID(&current->module->prefix, &binding->oid);
    SnmpErrorStatus status;
    if (cmp < 0) {
        return find_next_var(binding, current->right_child);
    } else if (cmp > 0) {
        status = find_next_var(binding, current->left_child);
        if (status != NO_ERROR || binding->type != SMI_EXCEPT_END_OF_MIB_VIEW) {
            return status;
        }
    }

    status = current->module->get_next_var(current->module, binding);
    if (status == NO_ERROR && binding->type == SMI_EXCEPT_END_OF_MIB_VIEW) {
        return find_next_var(binding, current->right_child);
    } else {
        return status;
    }
}

static MibTreeNode *add_module_to_subtree(MibTreeNode *new, MibTreeNode *current)
{
    int c = compare_OID(&current->module->prefix, &new->module->prefix);

    if (c > 0) {
        if (current->left_child == NULL) {
            current->left_child = new;
        } else {
            current->left_child = add_module_to_subtree(new, current->left_child);
        }
    } else if (c < 0) {
        if (current->right_child == NULL) {
            current->right_child = new;
        } else {
            current->right_child = add_module_to_subtree(new, current->right_child);
        }
    } else {
        uint8_t oid_dump[256];
        int too_long = encode_OID_to_dotted_string(&current->module->prefix,
                oid_dump, sizeof(oid_dump));
        syslog(LOG_ERR, "overlapping MIB modules with managed prefix : %s",
                too_long ? "OID too long" : (char *) oid_dump);
        return NULL;
    }

    UPDATE_HEIGHT(current);
    return balance_tree(current);
}

static MibTreeNode *balance_tree(MibTreeNode *node)
{
    MibTreeNode *root = node;

    if (get_left_height(node) > get_right_height(node) + 1) {
        if (get_left_height(node->left_child) < get_right_height(node->left_child)) {
            /* left-right case -> left rotation at sublevel */
            MibTreeNode *tmp = node->left_child;
            node->left_child = tmp->right_child;
            tmp->right_child = tmp->right_child->left_child;
            node->left_child->left_child = tmp;
        }

        /* left-left case -> right rotation */
        root = node->left_child;
        node->left_child = root->right_child;
        root->right_child = node;
        UPDATE_HEIGHT(root->left_child);
        UPDATE_HEIGHT(root->right_child);
    } else if (get_right_height(node) > get_left_height(node) + 1) {
        if (get_left_height(node->right_child) > get_right_height(node->right_child)) {
            /* right-left case -> right rotation at sublevel */
            MibTreeNode *tmp = node->right_child;
            node->right_child = tmp->left_child;
            tmp->left_child = tmp->left_child->right_child;
            node->right_child->right_child = tmp;
        }

        /* right-right case -> left rotation */
        root = node->right_child;
        node->right_child = root->left_child;
        root->left_child = node;
        UPDATE_HEIGHT(root->left_child);
        UPDATE_HEIGHT(root->right_child);
    }

    UPDATE_HEIGHT(root);
    return root;
}

static int get_left_height(const MibTreeNode *node)
{
    if (node->left_child == NULL) {
        return 0;
    } else {
        return node->left_child->height;
    }
}

static int get_right_height(const MibTreeNode *node)
{
    if (node->right_child == NULL) {
        return 0;
    } else {
        return node->right_child->height;
    }
}

static void free_tree(MibTreeNode *node)
{
    if (node != NULL) {
        free_tree(node->left_child);
        free_tree(node->right_child);
        node->module->finish_module(node->module);
        free(node);
    }
}

#ifdef DEBUG
void dump_mib_tree(void)
{
    syslog(LOG_DEBUG, "MIB Tree");

    uint8_t buf[256];
    dump_mib_subtree(root_node, " ", 1, buf);
}

static void dump_mib_subtree(const MibTreeNode *tree, uint8_t *prefix,
        int tail, uint8_t buf[])
{
    if (tree == NULL) {
        return;
    }

    int too_long = encode_OID_to_dotted_string(&tree->module->prefix, buf, 256);
    syslog(LOG_DEBUG, "%s%s── %s", prefix, tail ? "╰" : "├", too_long ? "N/A" : (char *) buf);

    uint8_t prefix_buf[256];
    snprintf(prefix_buf, sizeof(prefix_buf), "%s%s   ", prefix, tail ? " " : "│");
    dump_mib_subtree(tree->left_child, prefix_buf, tree->right_child == NULL, buf);
    dump_mib_subtree(tree->right_child, prefix_buf, 1, buf);
}
#endif
