/**
 * Static Flush+Reload tools.
 *
 * Aims to replace flush_reload.[hc]
 *
 * Having it use static values only allows the compiler to optimize (e.g. unroll loops)
 * it, which fights the prefetcher
 */
#pragma once

// L3 miss
#ifndef UARF_FRS_THRESH
#define UARF_FRS_THRESH 200
#endif

// Address of flush and reload buffer
#ifndef UARF_FRS_BUF_BASE
#define UARF_FRS_BUF_BASE 0x13200000ul
#endif

// Address of result array
#ifndef UARF_FRS_RES
#define UARF_FRS_RES 0x1800000ul
#endif

// Number of bits to leak
#ifndef UARF_FRS_SLOTS
#define UARF_FRS_SLOTS 8
#endif

// Distance between two entries in the buffer
#ifndef UARF_FRS_STRIDE_BITS
#define UARF_FRS_STRIDE_BITS 12
#endif
#define UARF_FRS_STRIDE (1UL << UARF_FRS_STRIDE_BITS)

// Offset into stride
#ifndef UARF_FRS_OFFSET
#define UARF_FRS_OFFSET 0x180
#if UARF_FRS_OFFSET != 0
#warning "Have non-zero FR offset!"
#endif
#endif

// Define to use a 2MB huge page for the buffer
// #define UARF_FRS_BUF_HUGE

#define UARF_FRS_BUF (UARF_FRS_BUF_BASE + UARF_FRS_OFFSET)

#ifdef UARF_FRS_BUF_HUGE
#define UARF_FRS_BUF_SIZE (ROUND_2MB_UP(UARF_FRS_SLOTS * UARF_FRS_STRIDE + PAGE_SIZE))
#else
#define UARF_FRS_BUF_SIZE (UARF_FRS_SLOTS * UARF_FRS_STRIDE + PAGE_SIZE)
#endif

#define UARF_FRS_RES_SIZE (UARF_FRS_SLOTS * sizeof(uint64_t))

#ifndef __ASSEMBLY__
#include "compiler.h"
#include "lib.h"
#include "log.h"
#include "mem.h"
#include "page.h"
#include <string.h>

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_FR
#endif

/**
 * Initialize static FR.
 */
static void __always_inline uarf_frs_init(void) {
    UARF_LOG_TRACE("()\n");

    // Assert nm_slots is power of two. Fr_reload_range only works for 2^n
    uarf_assert(IS_POW_TWO(UARF_FRS_SLOTS));

#ifdef UARF_FRS_BUF_HUGE
    uarf_map_huge_or_die(_ptr(UARF_FRS_BUF_BASE), UARF_FRS_BUF_SIZE);
#else
    uarf_map_or_die(_ptr(UARF_FRS_BUF_BASE), UARF_FRS_BUF_SIZE);
    madvise(_ptr(UARF_FRS_BUF_BASE), UARF_FRS_BUF_SIZE, MADV_HUGEPAGE);
#endif

    uarf_map_or_die(_ptr(UARF_FRS_RES), UARF_FRS_RES_SIZE);
    memset(_ptr(UARF_FRS_RES), 0, UARF_FRS_RES_SIZE);

    // Ensure it is not zero-page backed
    for (size_t i = 0; i < UARF_FRS_SLOTS; i++) {
        memset(_ptr(UARF_FRS_BUF_BASE + i * UARF_FRS_STRIDE), '0' + i, UARF_FRS_STRIDE);
    }
}

/**
 * Deinitialize static FR.
 */
static void __always_inline uarf_frs_deinit(void) {
    UARF_LOG_TRACE("()\n");

    uarf_unmap_or_die(_ptr(UARF_FRS_BUF_BASE), UARF_FRS_BUF_SIZE);
    uarf_unmap_or_die(_ptr(UARF_FRS_RES), UARF_FRS_RES_SIZE);
}

/**
 * Reset history back to zero.
 */
static void __always_inline uarf_frs_reset(void) {
    UARF_LOG_TRACE("()\n");
    memset(_ptr(UARF_FRS_RES), 0, UARF_FRS_RES_SIZE);
}

/**
 * Flush static FR but explicit buffer address.
 *
 * Used signaling a guest and the buffer maps to different HVA than the static ones.
 */
static void __always_inline uarf_frs_flush_buf(uint64_t buf_addr) {
    UARF_LOG_TRACE("()\n");

    uarf_mfence();
    for (uint64_t i = 0; i < UARF_FRS_SLOTS; i++) {
        volatile void *p = _ptr(buf_addr + i * UARF_FRS_STRIDE);
        uarf_clflush(p);
    }
    uarf_mfence(); // Required to enforce ordering of cl flush with subsequent
                   // memory operations on AMD
    uarf_sfence();
    uarf_lfence();
}

/**
 * Flush static FR.
 */
static void __always_inline uarf_frs_flush(void) {
    UARF_LOG_TRACE("()\n");
    uarf_frs_flush_buf(UARF_FRS_BUF);
}

/**
 * Reload static FR but explicit buffer address.
 */
static void __always_inline uarf_frs_reload_buf(uint64_t buf_addr) {
    UARF_LOG_TRACE("()\n");

    for (uint64_t k = 0; k < UARF_FRS_SLOTS; ++k) {
        uarf_reload_tlb(buf_addr + UARF_FRS_STRIDE * k);
    }
    uarf_mfence();

// Should be completely unrolled to prevent data triggering the data cache prefetcher
#if UARF_FRS_SLOTS > 8
#error "Increase the FR reload unroll factor"
#endif
#pragma GCC unroll 8
    for (uint64_t i = 0; i < UARF_FRS_SLOTS; i++) {
        // size_t buf_i = (i * 421 + 9) & (UARF_FRS_SLOTS - 1);
        size_t buf_i = (i * 13 + 9) & (UARF_FRS_SLOTS - 1);
        void *p = _ptr(buf_addr + UARF_FRS_STRIDE * buf_i);
        uint64_t dt = uarf_get_access_time(p);
        if (dt < UARF_FRS_THRESH) {
            ((uint64_t *) (UARF_FRS_RES))[buf_i]++;
        }
    }
    uarf_mfence();
}

/**
 * Reload static FR.
 */
static void __always_inline uarf_frs_reload(void) {
    UARF_LOG_TRACE("()\n");
    uarf_frs_reload_buf(UARF_FRS_BUF);
}

static void __always_inline uarf_frs_print(void) {
    UARF_LOG_TRACE("()\n");

    for (size_t i = 0; i < UARF_FRS_SLOTS; i++) {
        printf("%s%04lu " UARF_LOG_C_RESET,
               ((uint64_t *) UARF_FRS_RES)[i] ? UARF_LOG_C_DARK_RED : "",
               ((uint64_t *) UARF_FRS_RES)[i]);
    }
    printf("\n");
}

#endif /* __ASSEMBLY__ */
