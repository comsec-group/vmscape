/**
 * DLL Test
 *
 * Test the doubly linked list.
 */
#include "dll.h"
#include "lib.h"
#include "test.h"
#include <string.h>

// // Should be moved to dedicated testing file once we have a proper testing setup
// #include <assert.h>
// #include <stddef.h>
// #include <stdio.h>

// Init DLL and ensure head/tail sentinels are correctly initialized
UARF_TEST_CASE(initialize) {
    UarfDll dll;
    UarfDllNode head;
    UarfDllNode tail;

    // Initialize the DLL
    // Pass NULL as data, as we not not store any data
    uarf_dll_init(&dll, &head, NULL, &tail, NULL);
    uarf_assert(dll.head == &head);
    uarf_assert(dll.tail == &tail);
    uarf_assert(dll.head->next == &tail);
    uarf_assert(dll.tail->prev == &head);
    uarf_assert(dll.head->id == 0);
    uarf_assert(dll.tail->id == -1);
    UARF_TEST_PASS();
}

// Add element to dll
UARF_TEST_CASE(add_elem) {
    UarfDll dll;
    UarfDllNode head;
    UarfDllNode tail;
    uarf_dll_init(&dll, &head, NULL, &tail, NULL);

    UarfDllNode new;
    // Pass NULL as data, as we not not store any data
    uarf_dll_node_init(&dll, &new, NULL);
    uarf_assert(new.id == 1);

    uarf_dll_push_tail(&dll, &new);
    uarf_assert(dll.head->next == &new);
    uarf_assert(dll.tail->prev == &new);
    uarf_assert(dll.head == new.prev);
    uarf_assert(dll.tail == new.next);
    UARF_TEST_PASS();
}

UARF_TEST_SUITE() {
    UARF_TEST_RUN_CASE(initialize);
    UARF_TEST_RUN_CASE(add_elem);
    UARF_TEST_PASS();
}
