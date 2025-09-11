/**
 * Testing Infrastructure
 *
 * This tests the very basic testing infrastructure.
 */

#include "test.h"
#include <stdio.h>

UARF_TEST_CASE(hello_world) {
    printf("Hello, World\n");
    UARF_TEST_PASS();
}

UARF_TEST_CASE_ARG(hello_arg, arg) {
    UARF_TEST_ASSERT(_ul(arg) == 5);
    UARF_TEST_PASS();
}

UARF_TEST_SUITE() {
    UARF_TEST_RUN_CASE(hello_world);
    UARF_TEST_RUN_CASE_ARG(hello_arg, 5);
    return 0;
}
