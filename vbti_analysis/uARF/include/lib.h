#pragma once

#include "compiler.h"
#include "kmod/pi.h"
#include "kmod/rap.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef min
#define min(a, b)                                                                        \
    ({                                                                                   \
        const typeof(a) _a = (a);                                                        \
        const typeof(b) _b = (b);                                                        \
        _a < _b ? _a : _b;                                                               \
    })
#endif

#ifndef max
#define max(a, b)                                                                        \
    ({                                                                                   \
        const typeof(a) _a = (a);                                                        \
        const typeof(b) _b = (b);                                                        \
        _a > _b ? _a : _b;                                                               \
    })
#endif

#define div_round_up(n, d) ((((n) + (d)) - 1) / (d))

#define ROUND_2MB_UP(x) (((x) + 0x1fffffUL) & ~0x1fffffUL)

static __always_inline void uarf_sfence(void) {
    asm volatile("sfence" ::: "memory");
}

static __always_inline void uarf_lfence(void) {
    asm volatile("lfence" ::: "memory");
}

static __always_inline void uarf_mfence(void) {
    asm volatile("mfence" ::: "memory");
}

static __always_inline uint32_t uarf_get_seed(void) {
    uint32_t seed;
    asm volatile("rdrand %0" : "=r"(seed));
    return seed;
}

// Get a random 47 bit long number
static __always_inline uint64_t uarf_rand47(void) {
    return (_ul(rand()) << 16) ^ rand();
}

static __always_inline void uarf_clflush(const volatile void *p) {
    asm volatile("clflush %0" ::"m"(*(char const *) p) : "memory");
}

static __always_inline void uarf_prefetchw(const void *p) {
    asm volatile("prefetchw %0" ::"m"(*(char const *) p) : "memory");
}

static __always_inline void uarf_prefetcht0(const void *p) {
    asm volatile("prefetcht0 %0" ::"m"(*(char const *) p) : "memory");
}

static __always_inline void uarf_prefetcht1(const void *p) {
    asm volatile("prefetcht1 %0" ::"m"(*(char const *) p) : "memory");
}

static __always_inline void uarf_prefetcht2(const void *p) {
    asm volatile("prefetcht2 %0" ::"m"(*(char const *) p) : "memory");
}

static __always_inline void uarf_prefetchnta(const void *p) {
    asm volatile("prefetchnta %0" ::"m"(*(char const *) p) : "memory");
}

static __always_inline void uarf_cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                                       uint32_t *ecx, uint32_t *edx) {
    asm volatile("cpuid"
                 : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                 : "0"(leaf), "1"(*ebx), "2"(*ecx), "3"(*edx));
}

static __always_inline uint32_t uarf_cpuid_eax(uint32_t leaf) {
    uint32_t eax = 0, ign = 0;

    uarf_cpuid(leaf, &eax, &ign, &ign, &ign);
    return eax;
}

static __always_inline uint32_t uarf_cpuid_ebx(uint32_t leaf) {
    uint32_t ebx = 0, ign = 0;

    uarf_cpuid(leaf, &ign, &ebx, &ign, &ign);
    return ebx;
}

static __always_inline uint32_t uarf_cpuid_ecx(uint32_t leaf) {
    uint32_t ecx = 0, ign = 0;

    uarf_cpuid(leaf, &ign, &ign, &ecx, &ign);
    return ecx;
}

static __always_inline uint32_t uarf_cpuid_edx(uint32_t leaf) {
    uint32_t edx = 0, ign = 0;

    uarf_cpuid(leaf, &ign, &ign, &ign, &edx);
    return edx;
}

static __always_inline void uarf_cpuid_user(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                                            uint32_t *ecx, uint32_t *edx) {
    uarf_pi_cpuid(leaf, eax, ebx, ecx, edx);
}

static __always_inline uint32_t uarf_cpuid_eax_user(uint32_t leaf) {
    uint32_t eax;
    uarf_cpuid_user(leaf, &eax, NULL, NULL, NULL);
    return eax;
}

static __always_inline uint32_t uarf_cpuid_ebx_user(uint32_t leaf) {
    uint32_t ebx;
    uarf_cpuid_user(leaf, NULL, &ebx, NULL, NULL);
    return ebx;
}

static __always_inline uint32_t uarf_cpuid_ecx_user(uint32_t leaf) {
    uint32_t ecx;
    uarf_cpuid_user(leaf, NULL, NULL, &ecx, NULL);
    return ecx;
}

static __always_inline uint32_t uarf_cpuid_edx_user(uint32_t leaf) {
    uint32_t edx;
    uarf_cpuid_user(leaf, NULL, NULL, NULL, &edx);
    return edx;
}

/**
 * Read from MSR from privileged.
 */
static __always_inline uint64_t uarf_rdmsr(uint32_t msr_idx) {
    uint32_t low, high;

    asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr_idx));

    return (((uint64_t) high) << 32) | low;
}

/**
 * Read from MSR from user using PI module.
 */
static __always_inline uint64_t uarf_rdmsr_user(uint32_t msr) {
    return uarf_pi_rdmsr(msr);
}

/**
 * Write to MSR from privileged.
 */
static __always_inline void uarf_wrmsr(uint32_t idx, uint64_t value) {
    asm volatile("wrmsr" ::"c"(idx), "a"((uint32_t) value),
                 "d"((uint32_t) (value >> 32)));
}

/**
 * Write to MSR from user using PI module.
 */
static __always_inline void uarf_wrmsr_user(uint32_t idx, uint64_t value) {
    uarf_pi_wrmsr(idx, value);
}

/**
 * Set single bit in MSR to 1, leaving all others unchanged, from privileged.
 *
 * Reads the MSR.
 */
static __always_inline void uarf_wrmsr_set(uint64_t msr, size_t bit) {
    uarf_wrmsr(msr, BIT_SET(uarf_rdmsr(msr), bit));
}

/**
 * Set single bit in MSR to 1, leaving all others unchanged, from user.
 *
 * Reads the MSR.
 */
static __always_inline void uarf_wrmsr_set_user(uint64_t msr, size_t bit) {
    uarf_wrmsr_user(msr, BIT_SET(uarf_rdmsr_user(msr), bit));
}

/**
 * Set single bit in MSR to 0, leaving all others unchanged, from user.
 *
 * Reads the MSR.
 */
static __always_inline void uarf_wrmsr_clear(uint64_t msr, size_t bit) {
    uarf_wrmsr(msr, BIT_CLEAR(uarf_rdmsr(msr), bit));
}

/**
 * Set single bit in MSR to 0, leaving all others unchanged, from user.
 *
 * Reads the MSR.
 */
static __always_inline void uarf_wrmsr_clear_user(uint64_t msr, size_t bit) {
    uarf_wrmsr_user(msr, BIT_CLEAR(uarf_rdmsr_user(msr), bit));
}

// TODO: guard
// MSR settings are given as the bit position, not value
#define MSR_SPEC_CTRL               0x00000048
#define MSR_SPEC_CTRL__IBRS         0
#define MSR_SPEC_CTRL__STIBP        1
#define MSR_PRED_CMD                0x00000049
#define MSR_PRED_CMD__IBPB          0
#define MSR_EFER                    0xc0000080
#define MSR_EFER__AUTOMATIC_IBRS_EN 21
#define MSR_EFER__SCE               1
#define MSR_STAR                    0xc0000081
#define MSR_LSTAR                   0xc0000082

/**
 * Trigger an IBPB from privileged.
 */
static __always_inline void uarf_ibpb(void) {
    // Write only, error on read
    uarf_wrmsr(MSR_PRED_CMD, BIT(MSR_PRED_CMD__IBPB));
}

/**
 * Trigger an IBPB from user.
 */
static __always_inline void uarf_ibpb_user(void) {
    // Write only, error on read
    uarf_wrmsr_user(MSR_PRED_CMD, BIT(MSR_PRED_CMD__IBPB));
}

/**
 * Enable IBRS from privileged.
 */
static __always_inline void uarf_ibrs_on(void) {
    uarf_wrmsr_set(MSR_SPEC_CTRL, MSR_SPEC_CTRL__IBRS);
}

/**
 * Enable IBRS from user.
 */
static __always_inline void uarf_ibrs_on_user(void) {
    uarf_wrmsr_set_user(MSR_SPEC_CTRL, MSR_SPEC_CTRL__IBRS);
}

/**
 * Disable IBRS from privileged.
 */
static __always_inline void uarf_ibrs_off(void) {
    uarf_wrmsr_clear(MSR_SPEC_CTRL, MSR_SPEC_CTRL__IBRS);
}

/**
 * Disable IBRS from user.
 */
static __always_inline void uarf_ibrs_off_user(void) {
    uarf_wrmsr_clear_user(MSR_SPEC_CTRL, MSR_SPEC_CTRL__IBRS);
}

/**
 * Enable STIBP from privileged.
 */
static __always_inline void uarf_stibp_on(void) {
    uarf_wrmsr_set(MSR_SPEC_CTRL, MSR_SPEC_CTRL__STIBP);
}

/**
 * Enable STIBP from user.
 */
static __always_inline void uarf_stibp_on_user(void) {
    uarf_wrmsr_set_user(MSR_SPEC_CTRL, MSR_SPEC_CTRL__STIBP);
}

/**
 * Disable STIBP from privileged.
 */
static __always_inline void uarf_stibp_off(void) {
    uarf_wrmsr_clear(MSR_SPEC_CTRL, MSR_SPEC_CTRL__STIBP);
}

/**
 * Disable STIBP from user.
 */
static __always_inline void uarf_stibp_off_user(void) {
    uarf_wrmsr_clear_user(MSR_SPEC_CTRL, MSR_SPEC_CTRL__STIBP);
}

/**
 * Enable AutoIBRS from privileged.
 */
static __always_inline void uarf_autoibrs_on(void) {
    uarf_wrmsr_set(MSR_EFER, MSR_EFER__AUTOMATIC_IBRS_EN);
}

/**
 * Enable AutoIBRS from user.
 */
static __always_inline void uarf_autoibrs_on_user(void) {
    uarf_wrmsr_set_user(MSR_EFER, MSR_EFER__AUTOMATIC_IBRS_EN);
}

/**
 * Disable AutoIBRS from privileged.
 */
static __always_inline void uarf_autoibrs_off(void) {
    uarf_wrmsr_clear(MSR_EFER, MSR_EFER__AUTOMATIC_IBRS_EN);
}

/**
 * Disable AutoIBRS from user.
 */
static __always_inline void uarf_autoibrs_off_user(void) {
    uarf_wrmsr_clear_user(MSR_EFER, MSR_EFER__AUTOMATIC_IBRS_EN);
}

/**
 * Enable eIBRS from privileged.
 *
 * Systems supporting eIBRS do not have IBRS. But the same register is used.
 */
static __always_inline void uarf_eibrs_on(void) {
    uarf_ibrs_on();
}

/**
 * Enable eIBRS from user.
 *
 * Systems supporting eIBRS do not have IBRS. But the same register is used.
 */
static __always_inline void uarf_eibrs_on_user(void) {
    uarf_ibrs_on_user();
}

/**
 * Disable eIBRS from privileged.
 *
 * However, disabling eIBRS does usually not work.
 */
static __always_inline void uarf_eibrs_off(void) {
    uarf_ibrs_off();
}

/**
 * Disable eIBRS from user.
 *
 * However, disabling eIBRS does usually not work.
 */
static __always_inline void uarf_eibrs_off_user(void) {
    uarf_ibrs_off_user();
}

static __always_inline unsigned long uarf_read_cr3(void) {
    unsigned long cr3;

    asm volatile("mov %%cr3, %0" : "=r"(cr3));

    return cr3;
}

static __always_inline void uarf_write_cr3(unsigned long cr3) {
    asm volatile("mov %0, %%cr3" ::"r"(cr3));
}

static __always_inline unsigned long uarf_read_cr4(void) {
    unsigned long cr4;

    asm volatile("mov %%cr4, %0" : "=r"(cr4));

    return cr4;
}

static __always_inline void uarf_invlpg(void *addr) {
    asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
}

static __always_inline void uarf_invlpg_user(void *addr) {
    uarf_pi_invlpg(_ul(addr));
}

static __always_inline void uarf_flush_tlb(void) {
    uarf_write_cr3(uarf_read_cr3());
}

static __always_inline void uarf_flush_tlb_user(void) {
    uarf_pi_flush_tlb();
}

static __always_inline unsigned int uarf_get_cpl(void) {
    unsigned int cs;
    asm volatile("mov %%cs, %0" : "=r"(cs));
    return cs & 0x03;
}

static __always_inline uint64_t uarf_rdpmc(uint32_t index) {
    uint32_t lo, hi;
    asm volatile("rdpmc" : "=a"(lo), "=d"(hi) : "c"(index));
    return ((uint64_t) hi << 32) | lo;
}

#define uarf_assert(cond)                                                                \
    if (!(cond)) {                                                                       \
        fprintf(stderr, "%s: Assert at %d failed: %s\n", __func__, __LINE__,             \
                STR((cond)));                                                            \
        exit(1);                                                                         \
    }

static __always_inline void uarf_bug(void) {
    fprintf(stderr, "Hit a bug\n");
    exit(1);
}

static __always_inline uint64_t uarf_rdtsc(void) {
    unsigned int low, high;

    asm volatile("rdtsc" : "=a"(low), "=d"(high));

    return ((uint64_t) high << 32) | low;
}

static __always_inline uint64_t uarf_rdtscp(void) {
    unsigned int low, high;

    asm volatile("rdtscp" : "=a"(low), "=d"(high)::"ecx");

    return ((uint64_t) high << 32) | low;
}

/**
 * Read MPERF MSR from userspace, which is incremented by P0 frequency.
 */
static __always_inline uint64_t uarf_rdpru_mperf(void) {
    unsigned int low, high;

    asm volatile("rdpru" : "=a"(low), "=d"(high) : "c"(0));

    return ((uint64_t) high << 32) | low;
}

/**
 * Read APERF MSR from userspace, which is incremented by actual clock cycles.
 */
static __always_inline uint64_t uarf_rdpru_aperf(void) {
    unsigned int low, high;

    asm volatile("rdpru" : "=a"(low), "=d"(high) : "c"(1));

    return ((uint64_t) high << 32) | low;
}

/**
 * Get the number of cycles needed to read from `p`
 *
 * Used th rdtsc/p instructions
 */
static __always_inline uint64_t uarf_get_access_time(const void *p) {
    // TODO: Check right use of rdtsc(p) and barriers
    uarf_mfence();
    uarf_lfence();
    uint64_t t0 = uarf_rdtsc();
    uarf_mfence();
    *(volatile char *) p;
    uarf_mfence();
    t0 = uarf_rdtscp() - t0;
    uarf_mfence();
    uarf_lfence();
    return t0;
}

// Depends on optimisations!
#define UARF_ACCESS_TIME_A_OVERHEAD 57
/**
 * Get the number of cycles needed to read from `p`
 *
 * Used the APERF MSR
 *
 * Use same fences as "AMD Prefetch Attacks" paper
 *
 * Overhead: 57
 */
static __always_inline uint64_t uarf_get_access_time_a(const void *p) {
    uarf_mfence();
    uarf_lfence();
    uint64_t t0 = uarf_rdpru_aperf();
    uarf_lfence();
    *(volatile char *) p;
    uarf_lfence();
    t0 = uarf_rdpru_aperf() - t0;
    uarf_mfence();
    uarf_lfence();
    return t0 - UARF_ACCESS_TIME_A_OVERHEAD;
}

// Depends on optimisations!
#define UARF_ACCESS_TIME_M_OVERHEAD 135
/**
 * Get the number of cycles needed to read from `p`
 *
 * Used the MPERF MSR
 *
 * Use same fences as "AMD Prefetch Attacks" paper
 *
 * Overhead: 135
 */
static __always_inline uint64_t uarf_get_access_time_m(const void *p) {
    uarf_mfence();
    uarf_lfence();
    uint64_t t0 = uarf_rdpru_mperf();
    uarf_mfence();
    *(volatile char *) p;
    uarf_mfence();
    t0 = uarf_rdpru_mperf() - t0;
    uarf_mfence();
    uarf_lfence();
    return t0 - UARF_ACCESS_TIME_M_OVERHEAD;
}

static volatile uint64_t uarf_loc = 0;

/**
 * Get mean cached access time over `rounds` rounds.
 */
static uint64_t __always_inline uarf_get_access_time_cached(uint64_t rounds) {
    uint64_t dt = 0;
    for (uint64_t i = 0; i < rounds; i++) {
        uarf_mfence();
        uarf_lfence();
        *(volatile uint64_t *) &uarf_loc;
        dt += uarf_get_access_time(_ptr(&uarf_loc));
    }

    return dt / rounds;
}

/**
 * Get mean uncached access time over `rounds` rounds.
 */
static uint64_t __always_inline uarf_get_access_time_uncached(uint64_t rounds) {
    uint64_t dt = 0;
    for (uint64_t i = 0; i < rounds; i++) {
        uarf_mfence();
        uarf_lfence();
        uarf_clflush(_ptr(&uarf_loc));
        dt += uarf_get_access_time(_ptr(&uarf_loc));
    }

    return dt / rounds;
}
