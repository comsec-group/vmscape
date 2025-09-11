#pragma once

// Offsets into struct Data
// WARNING: Do not change without changing struct SpecData
#define UARF_DATA__spec_prim_p    0
#define UARF_DATA__spec_dst_p_p   8
#define UARF_DATA__fr_buf_p       16
#define UARF_DATA__secret         24
#define UARF_DATA__ustack_index   32
#define UARF_DATA__ustack_stack   40
#define UARF_DATA__ustack_scratch 168
#define UARF_DATA__istack_index   176
#define UARF_DATA__istack_stack   184
#define UARF_DATA__istack_scratch 312
#define UARF_DATA__ostack_index   320
#define UARF_DATA__ostack_stack   328
#define UARF_DATA__ostack_scratch 456
#define UARF_DATA__hist           464
#define UARF_DATA__hist_size      8
// #define DATA__hist_num   200

#define UARF_USTACK_INDEX_OFFSET   UARF_DATA__ustack_index
#define UARF_USTACK_STACK_OFFSET   UARF_DATA__ustack_stack
#define UARF_USTACK_SCRATCH_OFFSET UARF_DATA__ustack_scratch

#define UARF_ISTACK_INDEX_OFFSET   UARF_DATA__istack_index
#define UARF_ISTACK_STACK_OFFSET   UARF_DATA__istack_stack
#define UARF_ISTACK_SCRATCH_OFFSET UARF_DATA__istack_scratch

#define UARF_OSTACK_INDEX_OFFSET   UARF_DATA__ostack_index
#define UARF_OSTACK_STACK_OFFSET   UARF_DATA__ostack_stack
#define UARF_OSTACK_SCRATCH_OFFSET UARF_DATA__ostack_scratch

#ifndef __ASSEMBLY__
#include "compiler.h"
#include "kmod/rap.h"
#include "lib.h"
#include <stdint.h>

typedef struct UarfHistory UarfHistory;
struct UarfHistory {
    uint64_t hist[2];
};

#define UARF_CSTACK_LEN 16
typedef struct UarfCStack UarfCStack;
struct UarfCStack {
    uint64_t index;
    uint64_t buffer[UARF_CSTACK_LEN];
    uint64_t scratch;
} __packed;

// Holds all the values that a indirect branch stub requires
// WARNING: Adjust the DATA__ macros when changing this!
typedef struct UarfSpecData UarfSpecData;
struct UarfSpecData {
    uint64_t spec_prim_p;  // 0
    uint64_t spec_dst_p_p; // 8
    uint64_t fr_buf_p;     // 16
    uint64_t secret;       // 24
    UarfCStack ustack;     // 32
    UarfCStack istack;     // 176
    UarfCStack ostack;     // 320
    UarfHistory hist;      // 464 onwards
} __aligned(8) __packed;

__always_inline void uarf_cstack_push(UarfCStack *stk, uint64_t value) {
    uarf_assert(stk->index < UARF_CSTACK_LEN);
    stk->buffer[stk->index++] = value;
}

__always_inline uint64_t uarf_cstack_pop(UarfCStack *stk) {
    uarf_assert(stk->index >= 1);
    return stk->buffer[--stk->index];
}

__always_inline void uarf_cstack_reset(UarfCStack *stk) {
    *stk = (UarfCStack) {.index = 0, .buffer = {0}, .scratch = 0};
}

// Get an randomly initialized history
UarfHistory uarf_get_randomized_history(void);

static inline void uarf_clflush_spec_dst(const UarfSpecData *data) {
    uarf_clflush(_ptr(*(uint64_t *) data->spec_dst_p_p));
}

static inline void uarf_invlpg_spec_dst(const UarfSpecData *data) {
    uarf_invlpg(_ptr(*(uint64_t *) data->spec_dst_p_p));
}

static inline void uarf_prefetcht0_spec_dst(const UarfSpecData *data) {
    uarf_prefetcht0(_ptr(*(uint64_t *) data->spec_dst_p_p));
}

// Run the speculation primitive described by SpecData.
void uarf_run_spec(void *arg);

#endif // __ASSEMBLY__
