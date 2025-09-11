/**
 * Kernel Module PI (Privileged Instruction)
 *
 *
 */

#include "kmod/pi.h"
#include "lib.h"
#include "mem.h"
#include "test.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>

#define DEVICE "/dev/" DEVICE_NAME
#define ROUNDS 100

UARF_TEST_CASE(rdmsr_wrmsr) {

    uarf_pi_init();

    uint64_t val_orig = uarf_pi_rdmsr(0x48);

    uint64_t val_new = val_orig ^ 1;
    uarf_pi_wrmsr(0x48, val_new);

    uint64_t val_changed = uarf_pi_rdmsr(0x48);

    UARF_TEST_ASSERT((val_changed ^ 1) == val_orig);

    uarf_pi_wrmsr(0x48, val_orig);

    uint64_t val_final = uarf_pi_rdmsr(0x48);

    UARF_TEST_ASSERT(val_orig == val_final);

    uarf_pi_deinit();

    UARF_TEST_PASS();
}

UARF_TEST_CASE(invlpg) {
    uarf_pi_init();
    int *loc = uarf_malloc_or_die(sizeof(int));

    uint64_t t_c = 0;
    uint64_t t_n = 0;

    for (size_t i = 0; i < ROUNDS; i++) {
        *(volatile int *) loc = 0;

        uarf_mfence();

        t_c += uarf_get_access_time(loc);

        uarf_mfence();

        uarf_pi_invlpg(_ul(loc));

        uarf_mfence();

        t_n += uarf_get_access_time(loc);
    }

    t_c /= ROUNDS;
    t_n /= ROUNDS;

    UARF_LOG_DEBUG("TLB:    %lu\n", t_c);
    UARF_LOG_DEBUG("No TLB: %lu\n", t_n);

    UARF_TEST_ASSERT(t_c < t_n);

    uarf_free_or_die(loc);

    uarf_pi_deinit();

    UARF_TEST_PASS();
}

UARF_TEST_CASE(flush_tlb) {
    uarf_pi_init();
    int *loc = uarf_malloc_or_die(sizeof(int));

    uint64_t t_c = 0;
    uint64_t t_n = 0;

    for (size_t i = 0; i < ROUNDS; i++) {
        *(volatile int *) loc = 0;

        uarf_mfence();

        t_c += uarf_get_access_time(loc);

        uarf_mfence();

        uarf_pi_invlpg(_ul(loc));

        uarf_mfence();

        t_n += uarf_get_access_time(loc);
    }

    t_c /= ROUNDS;
    t_n /= ROUNDS;

    UARF_LOG_DEBUG("TLB:    %lu\n", t_c);
    UARF_LOG_DEBUG("No TLB: %lu\n", t_n);

    UARF_TEST_ASSERT(t_c < t_n);

    uarf_free_or_die(loc);

    uarf_pi_deinit();

    UARF_TEST_PASS();
}

UARF_TEST_CASE(cpuid) {
    uarf_pi_init();

    uint32_t eax, ebx, ecx, edx;

    uint32_t leaf = 0x80000021;

    uarf_cpuid(leaf, &eax, &ebx, &ecx, &edx);

    UARF_LOG_DEBUG("EAX: %x\n", eax);
    UARF_LOG_DEBUG("EBX: %x\n", ebx);
    UARF_LOG_DEBUG("ECX: %x\n", ecx);
    UARF_LOG_DEBUG("EDX: %x\n", edx);

    UARF_TEST_ASSERT(uarf_cpuid_eax(leaf) == eax);
    UARF_TEST_ASSERT(uarf_cpuid_ebx(leaf) == ebx);
    UARF_TEST_ASSERT(uarf_cpuid_ecx(leaf) == ecx);
    UARF_TEST_ASSERT(uarf_cpuid_edx(leaf) == edx);

    uarf_pi_deinit();
    UARF_TEST_PASS();
}

UARF_TEST_SUITE() {
    UARF_TEST_RUN_CASE(rdmsr_wrmsr);
    UARF_TEST_RUN_CASE(invlpg);
    UARF_TEST_RUN_CASE(flush_tlb);
    UARF_TEST_RUN_CASE(cpuid);

    return 0;
}
