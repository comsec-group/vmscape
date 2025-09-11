#pragma once

#include "compiler.h"
#include "log.h"
#include <stdlib.h>

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_TEST
#endif

#define UARF_TEST_CASE_PREFIX test_case_

#define UARF_TEST_CASE(name)                                                             \
    static unsigned long __noinline __text CAT(UARF_TEST_CASE_PREFIX, name)(void)

#define UARF_TEST_CASE_ARG(name, arg)                                                    \
    static unsigned long __noinline __text CAT(UARF_TEST_CASE_PREFIX, name)(void *arg)

#define UARF_TEST_SUITE() int main(void)

#define UARF_TEST_SUITE_ARG(argc, argv) int main(int argc, char **argv)

#define UARF_TEST_RUN_CASE(name, ...)                                                    \
    UARF_LOG_INFO("Run TestCase " STR(name) ": " __VA_ARGS__ "\n");                      \
    CAT(UARF_TEST_CASE_PREFIX, name)()

#define UARF_TEST_RUN_CASE_ARG(name, arg, ...)                                           \
    ({                                                                                   \
        UARF_LOG_INFO("Run TestCase " STR(name) ": " __VA_ARGS__ "\n");                  \
        unsigned long out = CAT(UARF_TEST_CASE_PREFIX, name)(_ptr(arg));                 \
        out;                                                                             \
    })

#define UARF_TEST_PASS() return 0
#define UARF_TEST_ASSERT(cond)                                                           \
    ({                                                                                   \
        if (!(cond)) {                                                                   \
            UARF_LOG_WARNING("%s: Assert at %d failed: %s\n", __func__, __LINE__,        \
                             STR((cond)));                                               \
            exit(1);                                                                     \
        }                                                                                \
    })

#define UARF_INIT_SRAND(var)                                                             \
    uint32_t var;                                                                        \
    asm("rdrand %0" : "=r"(var));                                                        \
    srand(var)
