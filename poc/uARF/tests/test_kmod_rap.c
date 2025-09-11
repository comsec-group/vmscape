/**
 * Kernel Module RAP (Run as Privileged)
 *
 * Test the RAP kernel module.
 */

#include "compiler.h"
#include "kmod/rap.h"
#include "lib.h"
#include "test.h"

#define ROUNDS 100

static void basic_run(void *data) {
    asm volatile("nop\n\t");
}

UARF_TEST_CASE(basic) {
    uarf_rap_init();

    uarf_rap_call(basic_run, NULL);

    uarf_rap_deinit();
    UARF_TEST_PASS();
}

static void argument_run(void *data) {
    uint64_t *a = (uint64_t *) data;
    *a = 7;
}

UARF_TEST_CASE(argument) {
    uarf_rap_init();

    uint64_t a = 5;

    uarf_rap_call(argument_run, &a);

    UARF_TEST_ASSERT(a == 7);

    uarf_rap_deinit();
    UARF_TEST_PASS();
}

static uint64_t return_value_run(void *data) {
    return uarf_read_cr3();
}

UARF_TEST_CASE(return_value) {
    uarf_rap_init();

    uint64_t ret = uarf_rap_call(return_value_run, NULL);
    printf("Got cr3: 0x%lx\n", ret);
    UARF_TEST_ASSERT(ret);

    uarf_rap_deinit();
    UARF_TEST_PASS();
}

UARF_TEST_SUITE() {
    UARF_TEST_RUN_CASE(basic);
    UARF_TEST_RUN_CASE(argument);
    UARF_TEST_RUN_CASE(return_value);

    return 0;
}
