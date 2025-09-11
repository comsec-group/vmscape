// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "lib.h"

// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#define _ul(a)  ((u64) (a))
#define _ptr(a) ((void *) (a))

#define _STR(x) #x
#define STR(x)  _STR(x)

typedef long i64;
typedef int i32;

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef double f64;
#define __aligned(x) __attribute__((aligned(x)))
#ifndef noinline
#define noinline __attribute__((noinline))
#endif

#include <sys/time.h>
static inline unsigned long get_ms(void) {
    static struct timeval tp;
    gettimeofday(&tp, 0);
    return tp.tv_sec * 1000 + tp.tv_usec / 1000;
}

/* Wait for all memory operations to complete before continuing. On AMD
 * processors, this also creates a new basic block. */
#define mb() asm("mfence" ::: "memory");

/* Wait for all memory loads to complete before continuing. This is also a
 * Speculation Barrier: speculative execution will stop here. However
 * instruction and data cache prefetchers can still continue to fetch. */
#define rmb() asm("lfence" ::: "memory");

/* Wait for all memory writes to complete before continuing. The weakest memory
 * barrier. */
#define wmb() asm("sfence" ::: "memory");

#define COLOR_GREEN  "\033[32m"
#define COLOR_RED    "\033[31m"
#define COLOR_BLUE   "\033[34m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_NC     "\033[0m"

#define COLOR_BG_RED  "\033[41m"
#define COLOR_BG_PRED "\033[101m"
#define COLOR_BG_GRN  "\033[42m"
#define COLOR_BG_PGRN "\033[102m"
#define COLOR_BG_YEL  "\033[43m"
#define COLOR_BG_PYEL "\033[103m"
#define COLOR_BG_BLU  "\033[44m"
#define COLOR_BG_PBLU "\033[104m"
#define COLOR_BG_MAG  "\033[45m"
#define COLOR_BG_PMAG "\033[105m"
#define COLOR_BG_CYN  "\033[46m"
#define COLOR_BG_PCYN "\033[106m"
#define COLOR_BG_WHT  "\033[47m"
#define COLOR_BG_PWHT "\033[107m"

#define INFO(...)    printf("\r[" COLOR_BLUE "-" COLOR_NC "] " __VA_ARGS__)
#define SUCCESS(...) printf("\r[" COLOR_GREEN "*" COLOR_NC "] " __VA_ARGS__)
#define ERROR(...)   printf("\r[" COLOR_RED "!" COLOR_NC "] " __VA_ARGS__)
#define DEBUG(...)   printf("\r[" COLOR_YELLOW "d" COLOR_NC "] " __VA_ARGS__)

#define KINFO(...)    printk("\r[" COLOR_BLUE "-" COLOR_NC "] " __VA_ARGS__)
#define KSUCCESS(...) printk("\r[" COLOR_GREEN "*" COLOR_NC "] " __VA_ARGS__)
#define KERROR(...)   printk("\r[" COLOR_RED "!" COLOR_NC "] " __VA_ARGS__)
#define KDEBUG(...)   printk("\r[" COLOR_YELLOW "d" COLOR_NC "] " __VA_ARGS__)
#define WARN          DEBUG

#ifndef RB_PTR
/* The Reload Buffel "RB" will take a hardcoded address so that it unlikely
 * neighboring other data */
#define RB_PTR 0x13200000UL
#endif
#ifndef RB_STRIDE
/* Each cache line that we flush+reload is separated by 4096 bytes */
#define RB_STRIDE (1UL << 12)
#endif
#ifndef RB_SLOTS
/* If we're just testing if a side channel works, we are fine with just a few
 * entries. To leak full bytes we would need 256 entries. */
#define RB_SLOTS 8
#endif
#ifndef SECRET
/* If we're just testing if a side channel works, we can aim at leaking a
 * pre-determined "secret" value. */
#define SECRET 6
#endif
#ifndef RB_OFFSET
#warning "I'm going to set the RB_OFFSET for you"
/* Rather than reloading a page-aligned address, we can pick something else.
 * The first few CLs of a page are more likely prefetched than others. */
#define RB_OFFSET 0x180
#endif
#ifndef RB_HIST
/* We keep the results in a histogram with RB_SLOTS bins. We give it a fixed
 * address too to make the reloading code position independent. */
#define RB_HIST 0x1800000
#endif

static u8 *rb = (u8 *) RB_PTR;
static u64 *rb_hist = (u64 *) RB_HIST;

#define ROUND_2MB_UP(x) (((x) + 0x1fffffUL) & ~0x1fffffUL)
#define RB_SZ           ROUND_2MB_UP((RB_SLOTS * RB_STRIDE) + 0x1000UL)
#define MMAP_FLAGS      (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE)

/* start measure */
static __always_inline u64 rb_rdtsc(void) {
    unsigned lo, hi;
    asm volatile("lfence\n\t"
                 "rdtsc\n\t"
                 : "=d"(hi), "=a"(lo));
    return ((u64) hi << 32) | lo;
}

/* stop measure */
static __always_inline u64 rb_rdtscp(void) {
    unsigned lo, hi;
    asm volatile("rdtscp\n\t"
                 "lfence\n\t"
                 : "=d"(hi), "=a"(lo)::"ecx");
    return ((u64) hi << 32) | lo;
}

static __always_inline void flush(void *p) {
    asm volatile("mfence		\n"
                 "clflush 0(%[p])	\n"
                 :
                 : [p] "c"(p)
                 : "rax");
}

/* it's generally better to hardcode hit/miss threshold than to compute it:
 * 1. threshold becomes an immediate
 * 2. calibrating requires a warmup to get stable value => slow.
 * The following should detect LLC misses on all microarchs. */
#ifndef CACHE_MISS_THRES
#define CACHE_MISS_THRES 120
#endif

static __always_inline void reload_one(long addr, u64 *results) {
    unsigned volatile char *p = (u8 *) addr;
    u64 t0 = rb_rdtsc();
    *(volatile unsigned char *) p;
    u64 dt = rb_rdtscp() - t0;
    if (dt < CACHE_MISS_THRES)
        results[0]++;
}

/**
 * Load n memory locations, separated by stride bytes, accessing them at some
 * offset different from RB_OFFSET to only make sure the respective page is in
 * the TLB. This code kind of assumes stride is a multiple of pages.. It may not
 * be necessary if not switching address space.
 */
static __always_inline void reload_tlb(long base, long stride, int n) {
    u64 poff = (base + 0x800) & 0xfff;
    for (u64 k = 0; k < n; ++k) {
        unsigned volatile char *p = (u8 *) base + poff + (stride * k);
        *(volatile unsigned char *) p;
    }
}

/**
 * Reload the n cache lines used for flush+reload. If access time is below the
 * threshold, increment the respective counter for the histogram/results.
 */
static __always_inline void reload_range(long base, long stride, int n, u64 *results) {
    reload_tlb(base, stride, n);
    mb();
    /* unroll the loop to avoid triggering data cache prefetcher. */
#pragma clang loop unroll(full)
    for (u64 k = 0; k < n; ++k) {
        /* semi-randomize the reload-order to avoid triggering data cache
         * prefetcher */
        u64 c = (k * 13 + 9) & (n - 1);
        unsigned volatile char *p = (u8 *) base + (stride * c);
        u64 t0 = rb_rdtsc();
        *(volatile unsigned char *) p;
        u64 dt = rb_rdtscp() - t0;
        if (dt < CACHE_MISS_THRES)
            results[c]++;
    }
}

static __always_inline void rb_reload_static(void) {

    // for (u64 k = 0; k < RB_SLOTS; ++k) {
    //     void *p = RB_PTR + RB_STRIDE * k;
    //     uarf_reload_tlb(_ul(p));
    // }
    mb();

    // Should be completely unrolled to prevent data triggering the data cache prefetcher
#pragma GCC unroll 1024
    for (u64 k = 0; k < RB_SLOTS; ++k) {
        size_t buf_i = (k * 421 + 9) & (RB_SLOTS - 1);
        // size_t buf_i = (k * 13 + 9) & (FR_SLOTS - 1);
        void *p = _ptr(RB_PTR + RB_OFFSET + RB_STRIDE * buf_i);
        u64 dt = uarf_get_access_time(p);
        if (dt < 200) {
            ((uint64_t *) (RB_HIST))[buf_i]++;
        }
    }
    uarf_mfence();
}

/**
 * Flush all the cachelines used for flush+reload.
 */
static __always_inline void flush_range(long start, long stride, int n) {
    mb();
    for (u64 k = 0; k < n; ++k) {
        volatile void *p = (u8 *) start + k * stride;
        asm volatile("clflushopt %0\n" ::"m"(*(const char *) p));
    }
    wmb();
    rmb();
}

/**
 * Initialize flush+reload buffer referenced by (RB_PTR) and the results
 * (RB_HIST).
 */
static __always_inline void rb_init(void) {
    /* Histogram, or simply put, the results. */
    if (mmap((void *) RB_HIST, RB_SLOTS * sizeof(u64), PROT_READ | PROT_WRITE,
             MMAP_FLAGS | MAP_POPULATE, -1, 0) == MAP_FAILED) {
        err(1, "rb_hist");
    }
    rb_hist = (u64 *) RB_HIST;

    if (mmap((void *) RB_PTR, RB_SZ, PROT_READ | PROT_WRITE, MMAP_FLAGS, -1, 0) ==
        MAP_FAILED) {
        err(1, "rb");
    }

    /* Try to make this page a single 2MB page, to avoid TLB missing when
     * reloading. */
    madvise((void *) RB_PTR, RB_SZ, MADV_HUGEPAGE);
    memset((void *) RB_PTR, 0xcc, RB_SZ);
}

/**
 * Any entry with hits > min?
 */
static __always_inline int rb_hits(int min) {
    for (int i = 0; i < RB_SLOTS; ++i) {
        if (rb_hist[i] > min) {
            return 1;
        }
    }
    return 0;
}

static __always_inline int rb_anyhit(void) {
    return rb_hits(0);
}

/**
 * Convenience macros.
 */
#define rb_reset()       memset(rb_hist, 0, RB_SLOTS * sizeof(*rb_hist))
#define rb_flush()       flush_range(RB_PTR + RB_OFFSET, RB_STRIDE, RB_SLOTS);
#define rb_reload()      reload_range(RB_PTR + RB_OFFSET, RB_STRIDE, RB_SLOTS, rb_hist);
#define rb_reload_one(i) reload_one(RB_PTR + i * RB_STRIDE + RB_OFFSET, &rb_hist[i]);
#define rb_print()                                                                       \
    do {                                                                                 \
        for (int i = 0; i < RB_SLOTS; ++i) {                                             \
            printf("%04ld ", rb_hist[i]);                                                \
        }                                                                                \
        printf("\n");                                                                    \
    } while (0)

static char strengths[][8] = {
    COLOR_BG_WHT,  COLOR_BG_PWHT, COLOR_BG_PMAG, COLOR_BG_MAG,
    COLOR_BG_PYEL, COLOR_BG_YEL,  COLOR_BG_PGRN, COLOR_BG_GRN,
};

/**
 * Find the reload buffer entry that had the most hits.
 */
static size_t rb_max_index(size_t *results, long max_byte) {
    size_t max = 0x0;
    for (size_t c = 0x1; c <= max_byte; ++c) {
        if (results[c] > results[max])
            max = c;
    }
    return max;
}

static int sorted_idx[RB_SLOTS];

/**
 * Find the `n` reload buffer entries that had the most hits.
 */
static inline int *rb_sort(size_t *results, long n) {
    static size_t tmp[RB_SLOTS];
    memset(sorted_idx, 0xff, RB_SLOTS * sizeof(*sorted_idx));
    memcpy(tmp, results, n * sizeof(*results));
    for (int i = 0; i < n; ++i) {
        int maxi = rb_max_index(tmp, RB_SLOTS - 1);
        if (maxi == 0)
            break;
        sorted_idx[i] = maxi;
        tmp[maxi] = 0;
    }
    return sorted_idx;
}

#define RB_ARR_SZ(a) (sizeof(a) / sizeof(*a))

/* To print the Histogram/results as a single-row heatmap */
static char rb_heat[0x1000];

static inline char *gen_rb_heat(void) {
    int maxi = rb_max_index(rb_hist, RB_SLOTS - 1);
    char *cursor = rb_heat;
    for (int i = 0; i < RB_SLOTS; ++i) {
        int x = 0;
        if (rb_hist[maxi] > 0) {
            x = (rb_hist[i] * RB_ARR_SZ(strengths) / rb_hist[maxi]) - 1;
        }
        char *color = strengths[x == -1 ? 0 : x];
        cursor += sprintf(cursor, "%s  " COLOR_NC, color);
    }

    return rb_heat;
}

static inline void rb_print_color(u64 rounds) {
    u64 *results = rb_hist;
    int maxi = rb_max_index(results, RB_SLOTS - 1);
    INFO("RB heat: %s", gen_rb_heat());
    printf(" guess=0x%x; n=%02ld; %02.3f", maxi, results[maxi],
           results[maxi] / (.0 + rounds));

    if (results[maxi] >= rounds * 0.95) {
        printf(" " COLOR_BG_GRN "Perfect!" COLOR_NC "\n");
    }
    else {
        printf("\n");
    }
}
