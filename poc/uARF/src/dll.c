// #include <stddef.h>
#include <string.h>

#include "dll.h"
#include "lib.h"

#include "log.h"

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_DLL
#endif

/**
 * Insert node `new` between node `previous` and `next`.
 *
 * @param new       new node to insert
 * @param previous  node after which to insert `new`
 * @param next      node before with to insert `new`
 *
 * note `previous` and `next` need to be neighbours
 */
void uarf_dll_insert_inbetween(UarfDllNode *new, UarfDllNode *previous,
                               UarfDllNode *next) {
    UARF_LOG_TRACE("(%p, %p, %p)\n", new, previous, next);
    uarf_assert(new != NULL &&previous != NULL &&next != NULL);
    uarf_assert(previous->next == next && previous == next->prev);
    // uarf_assert(new->prev == NULL &&new->next == NULL); // Can be removed if
    // required

    new->prev = previous;
    new->next = next;
    previous->next = new;
    next->prev = new;
}

/**
 * Insert node `new` after a node `previous`.
 *
 * @param new       new node to insert
 * @param previous  node after which to insert `new`
 */
void uarf_dll_push_after(UarfDllNode *new, UarfDllNode *previous) {
    UARF_LOG_TRACE("(%p, %p)\n", new, previous);
    uarf_assert(new != NULL &&previous != NULL);
    uarf_assert(previous->next->prev == previous);
    // uarf_assert(new->prev == NULL &&new->next == NULL); // Can be removed if
    // required

    uarf_dll_insert_inbetween(new, previous, previous->next);
}

/**
 * Insert node before a specific other node.
 *
 * @param new       new node to insert
 * @param next      node before with to insert `new`
 */
void uarf_dll_push_before(UarfDllNode *new, UarfDllNode *next) {
    UARF_LOG_TRACE("(%p, %p)\n", new, next);
    uarf_assert(new != NULL &&next != NULL);
    uarf_assert(next->prev->next == next);
    uarf_assert(new->prev == NULL &&new->next == NULL); // Can be removed if required

    uarf_dll_insert_inbetween(new, next->prev, next);
}

/**
 * Insert node at the tail.
 *
 * @param dll   pointer to dll
 * @param new   new node to insert
 *
 * This assumes that the last node is always a sentinel node!
 */
void uarf_dll_push_tail(UarfDll *dll, UarfDllNode *new) {
    UARF_LOG_TRACE("(%p, %p)\n", dll, new);
    uarf_assert(dll != NULL && new != NULL);
    uarf_assert(dll->head != NULL && dll->tail != NULL);
    uarf_assert(new->prev == NULL &&new->next == NULL); // Can be removed if required
    uarf_assert(dll->tail->type == UARF_DLL_NODE_TYPE_TAIL);

    uarf_dll_push_before(new, dll->tail);
}

/**
 * Remove `node`
 *
 * @param node to remove
 */
void uarf_dll_remove(UarfDllNode *node) {
    UARF_LOG_TRACE("(%p)\n", node);
    uarf_assert(node != NULL);
    uarf_assert(node->prev->next == node);
    uarf_assert(node->next->prev == node);

    node->prev->next = node->next;
    node->next->prev = node->prev;
}

/**
 * Initialize a new doubly linked list
 *
 * @param dll       pointer to dll to initialize
 * @param head      pointer to (uninitialized) node that acts as head sentinel
 * @param head_data pointer to the data of the head node (can be NULL)
 * @param tail      pointer to (uninitialized) node that acts as tail sentinel
 * @param tail_data pointer to the data of the tail node (can be NULL)
 *
 * The head node gets ID 0, while the tail node gets ID -1
 */
void uarf_dll_init(UarfDll *dll, UarfDllNode *head, void *head_data, UarfDllNode *tail,
                   void *tail_data) {
    UARF_LOG_TRACE("(%p, %p, %p, %p, %p)\n", dll, head, head_data, tail, tail_data);
    uarf_assert(dll != NULL && head != NULL && tail != NULL);
    // uarf_assert(dll->head == NULL && dll->tail == NULL);

    *head = (UarfDllNode) {.id = 0,
                           .prev = NULL,
                           .next = tail,
                           .data = head_data,
                           .type = UARF_DLL_NODE_TYPE_HEAD};
    *tail = (UarfDllNode) {.id = -1,
                           .prev = head,
                           .next = NULL,
                           .data = tail_data,
                           .type = UARF_DLL_NODE_TYPE_TAIL};

    *dll = (UarfDll) {.current_id = 0, .head = head, .tail = tail};
}

/**
 * Initialize a data node, which is to be inserted
 *
 *  Do not use for the initialization of sentinel nodes!
 *
 * @param dll   pointer to an initialized dll
 * @param node  pointer to node to initialize
 * @param data  pointer to the data of the new node
 */
void uarf_dll_node_init(UarfDll *dll, UarfDllNode *node, void *data) {
    UARF_LOG_TRACE("(%p, %p, %p)\n", dll, node, data);
    uarf_assert(dll != NULL && node != NULL);

    *node = (UarfDllNode) {.id = ++dll->current_id,
                           .prev = NULL,
                           .next = NULL,
                           .data = data,
                           .type = UARF_DLL_NODE_TYPE_NORMAL};
}

/**
 * Print a single node using `printf`
 *
 * @param node  node to print
 */
void uarf_dll_node_print(UarfDllNode *node) {
    UARF_LOG_TRACE("(%p)\n", node);
    char buf[256];
    if (node->type == UARF_DLL_NODE_TYPE_HEAD) {
        uarf_assert(node->prev == NULL);
        snprintf(buf, 256, "NULL ");
    }
    else {
        snprintf(buf, 256, "%d ", node->prev->id);
    }

    snprintf(buf + strlen(buf), 256, "<- %d ->", node->id);

    if (node->type == UARF_DLL_NODE_TYPE_TAIL) {
        uarf_assert(node->next == NULL);
        snprintf(buf + strlen(buf), 256, " NULL");
    }
    else {
        snprintf(buf + strlen(buf), 256, " %d", node->next->id);
    }
    UARF_LOG_DEBUG("%s\n", buf);
}

/**
 * Print out all nodes of the dll using `printf`
 *
 * @param dll   dll to print
 */
void uarf_dll_print_from_head(UarfDll *dll) {
    UARF_LOG_TRACE("(%p)\n", dll);
    if (dll->head == NULL) {
        printf("NULL ->");
    }
    else {
        printf("%d ->", dll->head->id);
    }

    uarf_dll_for_each(dll, c) {
        printf("(");
        uarf_dll_node_print(c);
        printf(")");
    }

    if (dll->tail == NULL) {
        printf("<- NULL\n");
    }
    else {
        printf("<- %d\n", dll->tail->id);
    }
}

/**
 * Get the number of non-sentiell nodes in the `dll`.
 *
 * @param dll dll to get size of
 */
size_t uarf_dll_size(UarfDll *dll) {
    UARF_LOG_TRACE("(%p)\n", dll);

    size_t len = 0;
    uarf_dll_for_each(dll, elem) {
        if (elem->type == UARF_DLL_NODE_TYPE_NORMAL) {
            len++;
        }
    }

    return len;
}

/**
 * Remove all elements of `dll` there `filter` is false.
 */
void uarf_dll_filter(UarfDll *dll, bool filter(UarfDllNode *node)) {
    UARF_LOG_TRACE("(%p, %p)\n", dll, filter);
    uarf_dll_for_each(dll, elem) {
        if (elem->type != UARF_DLL_NODE_TYPE_NORMAL) {
            continue;
        }

        if (!filter(elem)) {
            uarf_dll_remove(elem);
        }
    }
}
