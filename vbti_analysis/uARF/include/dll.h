/**
 * Implementation of a doubly linked list (DLL)
 *
 * The doubly-linked list `UarrfDll` is intended to be used with two sentinel nodes at the
 * head and tail. This simplifies many operations, as we do not have to deal with the
 * possibility of having null pointers.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * A node can either be a start or an end sentinel, or a normal node.
 */
typedef enum UarfDllNodeType UarfDllNodeType;
enum UarfDllNodeType {
    UARF_DLL_NODE_TYPE_HEAD = 0,
    UARF_DLL_NODE_TYPE_TAIL = 1,
    UARF_DLL_NODE_TYPE_NORMAL = 2,
};

/**
 * Represents a node.
 */
typedef struct UarfDllNode UarfDllNode;
struct UarfDllNode {
    int id;               /// Unique id of the node. For debugging
    UarfDllNode *prev;    /// Point to previous node in DLL
    UarfDllNode *next;    /// Point to next node in DLL
    void *data;           /// Pointer to the generic data
    UarfDllNodeType type; /// Type of the node
};

/**
 * Represents a doubly linked list.
 */
typedef struct UarfDll UarfDll;
struct UarfDll {
    int current_id;    /// Keep track of given IDs
    UarfDllNode *head; /// Point to head node
    UarfDllNode *tail; /// Point to tail node
};

// Iterative over whole `dll`. `elem` is the variable that can be used in the body
#define uarf_dll_for_each(dll, elem)                                                     \
    for (UarfDllNode *elem = (dll)->head; elem != NULL; elem = elem->next)

void uarf_dll_init(UarfDll *dll, UarfDllNode *head, void *head_data, UarfDllNode *tail,
                   void *tail_data);
void uarf_dll_node_init(UarfDll *dll, UarfDllNode *node, void *data);
void uarf_dll_push_tail(UarfDll *dll, UarfDllNode *new);
void uarf_dll_insert_inbetween(UarfDllNode *new, UarfDllNode *previous,
                               UarfDllNode *next);
void uarf_dll_push_after(UarfDllNode *new, UarfDllNode *previous);
void uarf_dll_push_before(UarfDllNode *new, UarfDllNode *next);
void uarf_dll_node_print_node(UarfDllNode *node);
void uarf_dll_print_from_head(UarfDll *dll);
void uarf_dll_remove(UarfDllNode *node);
size_t uarf_dll_size(UarfDll *dll);
void uarf_dll_filter(UarfDll *dll, bool filter(UarfDllNode *node));
