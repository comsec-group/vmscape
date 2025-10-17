#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define ROUNDS       (1 << 12)
#define MAX_CHAIN    128
#define CHAIN_OFFSET (512 + 8)

#define CACHE_MISS_THRES 300
#define SECRET           0
#define RB_OFFSET        (0xcc0 + MAX_CHAIN * 8192 + 4096)
#define RB_SLOTS         2
#include "compiler.h"
#include "jita.h"
#include "lib.h"
#include "log.h"
#include "psnip.h"
#include "rb_tools.h"

#define PAGE_4K     (4096UL)
#define PAGE_2M     (512 * PAGE_4K)
#define PAGE_1G     (512 * PAGE_2M)
#define PROT_RW     (PROT_READ | PROT_WRITE)
#define PROT_RWX    (PROT_RW | PROT_EXEC)
#define PG_ROUND(n) (((((n) - 1UL) >> 12) + 1) << 12)

#define HVA_SRC 0x555555de4cc1
#define HVA_DST 0x555555bfc295

// clang-format off
uarf_psnip_declare_define(psnip_src,
    "call *0x8(%rax)\n\t"
    "ret\n\t"
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

#if defined(MARCH_ZEN5)
#define NUM_MEASUREMENTS 8
#define EVICT_ITERATIONS 2
#define L1_SETS          64
#define L1_SET_SIZE      12
#define L2_EVICTION_SIZE 18
#define L2_SETS          1024
#define L2_FREE_SHIFT    16
#define L2_2MB_SET_SIZE  32
#define L2_1GB_SET_SIZE  1024 // max 8192
#define L3_SETS          32 * 1024
#define L3_SET_SIZE      32
#elif defined(MARCH_ZEN4)
#define NUM_MEASUREMENTS 32
#define EVICT_ITERATIONS 1
#define L1_SETS          64
#define L1_SET_SIZE      8
#define L2_EVICTION_SIZE 16
#define L2_SETS          2048
#define L2_FREE_SHIFT    17
#define L2_2MB_SET_SIZE  16
#define L2_1GB_SET_SIZE  512 // max 8192
#define L3_SETS          32 * 1024
#define L3_SET_SIZE      64
#else
#error "Unknown microarchitecture"
#endif

#define L1_THRESH  0
#define L2_THRESH  10
#define L3_THRESH  30
#define RAM_THRESH 300

typedef struct actxt {
    uint64_t entry_point;
} actxt_t;

volatile uint64_t *l2_sets[L2_SETS][L2_1GB_SET_SIZE] = {0};
volatile uint64_t *l1_sets[L1_SETS][L1_SET_SIZE] = {0};
uint64_t l2_sets_offset = 0;
uint64_t measurements[NUM_MEASUREMENTS];
uint64_t dummy_val[MAX_CHAIN];
uint64_t dst_ptr[2];
uint64_t dst_train_ptr[2];

static int stats_compare_u64(const void *a, const void *b) {
    return *(uint64_t *) a > *(uint64_t *) b;
}

uint64_t stats_median_u64(uint64_t *arr, uint64_t arr_len) {
    if (!arr_len) {
        UARF_LOG_ERROR("0 length array has no median\n");
        exit(1);
    }

    uint64_t *copy = calloc(arr_len, sizeof(*arr));
    if (!copy) {
        UARF_LOG_ERROR("failed to temp arr\n");
        exit(1);
    }

    memcpy(copy, arr, arr_len * sizeof(*arr));
    qsort(copy, arr_len, sizeof(*arr), stats_compare_u64);

    uint64_t median = copy[arr_len / 2];

    free(copy);

    return median;
}

uint64_t measure_eviction(volatile uint64_t *victim_ptr, volatile uint64_t **eviction_set,
                          uint64_t set_size) {
    for (int i = 0; i < NUM_MEASUREMENTS; ++i) {
        for (int r = 0; r < EVICT_ITERATIONS; ++r) {
            for (int e = 0; e < set_size; ++e) {
                *eviction_set[e];
                uarf_lfence();
            }
        }
        uarf_mfence();
#ifdef RDPRU_AVAILABLE
        uint64_t start = rb_rdpru();
#else
        uint64_t start = rb_rdtsc();
#endif
        uarf_lfence();
        *victim_ptr;
        uarf_lfence();
#ifdef RDPRU_AVAILABLE
        uint64_t end = rb_rdpru();
#else
        uint64_t end = rb_rdtscp();
#endif
        measurements[i] = end - start;
    }
    uint64_t median = stats_median_u64(measurements, NUM_MEASUREMENTS);
    return median;
}

uint64_t measure_self_eviction(volatile uint64_t **eviction_set) {
    for (int i = 0; i < NUM_MEASUREMENTS; ++i) {
        uint64_t start = rb_rdtsc();
        uarf_lfence();
        for (int e = 0; e < L2_EVICTION_SIZE; ++e) {
            *eviction_set[e];
        }
        uarf_lfence();
        uint64_t end = rb_rdtscp();
        measurements[i] = end - start;
    }
    uint64_t median = stats_median_u64(measurements, NUM_MEASUREMENTS);

    return median;
}

uint8_t check_self_eviction(volatile uint64_t **eviction_set, uint64_t baseline) {

    return measure_self_eviction(eviction_set) > baseline + 100;
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
    return 1;
}

uint8_t build_l2_sets(uint64_t mem_ptr,
                      volatile uint64_t *l2_sets[L2_SETS][L2_1GB_SET_SIZE]) {
    static volatile uint64_t *l2_set_wip[L2_SETS][L2_2MB_SET_SIZE] = {0};

    // reset state
    memset(l2_set_wip, 0, sizeof(l2_set_wip[0][0]) * L2_SETS * L2_2MB_SET_SIZE);
    memset(l2_sets, 0, sizeof(l2_sets[0][0]) * L2_SETS * L2_1GB_SET_SIZE);
    l2_sets_offset = 0;

    volatile uint64_t *dummy_set[L2_EVICTION_SIZE] = {0};
    for (uint64_t i = 0; i < L2_EVICTION_SIZE; ++i) {
        dummy_set[i] = (volatile uint64_t *) (_ul(mem_ptr) + (i << 17) + (i << 12));
    }
    uint64_t baseline = measure_self_eviction(dummy_set);
    printf("collective baseline: %ld\n", baseline);

    // find the first 2MB page where we can build all the sets
    for (uint64_t offset_2m = 4; offset_2m < PAGE_1G / PAGE_2M; ++offset_2m) {
        uint64_t base_2m = mem_ptr + (offset_2m << 21);

        // build the sets within the 2MB pages
        uint64_t offset_6b = 0;
        for (; offset_6b < L2_SETS; ++offset_6b) {
            uint64_t base_set = base_2m + (offset_6b << 6);

            for (uint64_t index = 0; index < L2_2MB_SET_SIZE; ++index) {
                l2_set_wip[offset_6b][index] =
                    (volatile uint64_t *) (base_set + (index << L2_FREE_SHIFT) + index);
            }

            if (!check_self_eviction(l2_set_wip[offset_6b], baseline)) {
                break;
            }

            if (offset_6b % 64 == 63) {
            }
        }

        // only continue if we found good eviction sets within this page
        if (offset_6b == L2_SETS) {
            // if this is the first one, just copy over all the sets
            uint64_t num_ok = 0;
            int64_t set_xor = 0;
            for (int64_t i = 0; i < L2_SETS; ++i) {
                // we can calculate a decent heuristic to speed up the
                // collision search
                int64_t search_start = i ^ set_xor;

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
                        for (int64_t j = 0; j < L2_SETS; ++j) {
                            int64_t cur_index = (search_start + j) % L2_SETS;
                            if (check_cross_eviction(l2_sets[cur_index], l2_set_wip[i],
                                                     baseline)) {
                                if (hit_index != -1) {
                                    UARF_LOG_ERROR("mutlihit\n");
                                    exit(1);
                                }
                                hit_index = cur_index;
                                set_xor = cur_index ^ i;
                                break; // remove this to check the precision of our
                                       // approach
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
    return 0;
}

static void swap_elements(uint64_t **set, size_t index_1, size_t index_2) {
    uint64_t *tmp = set[index_1];
    set[index_1] = set[index_2];
    set[index_2] = tmp;
}
static void shuffle_array(uint64_t **set, size_t size) {
    if (size == 0)
        return;
    for (size_t i = size - 1; i > 0; --i) {
        size_t j = rand() % (i + 1);
        swap_elements(set, j, i);
    }
}

void measure_window_size(actxt_t *ctxt, volatile uint64_t **eviction_sets,
                         uint64_t num_eviction_set, uint64_t eviction_set_size,
                         uint64_t eviction_set_total, uint64_t threshold, char *label) {
    uint64_t baseline = measure_eviction(&dst_ptr[1], NULL, 0);

    // try to find the right eviction set
    int set_index = -1;
    int64_t access_time = 0;
    for (int set = 0; set < num_eviction_set; ++set) {
        access_time =
            measure_eviction(&dst_ptr[1], &eviction_sets[set * eviction_set_total],
                             eviction_set_size) -
            baseline;
        if (access_time >= threshold) {
            // printf("time %ld\n", access_time);
            set_index = set;
            break;
        }
    }
    if (access_time >= RAM_THRESH) {
        printf("evicted from L3\n");
    }
    else if (access_time > L2_THRESH) {
        printf("evicted from L2\n");
    }
    else if (access_time > L1_THRESH) {
        printf("evicted from L1\n");
    }
    else {
        printf("target in L1\n");
    }
    if (num_eviction_set != 0 && set_index == -1) {
        UARF_LOG_ERROR("set not found\n");
    }

    uint64_t *rb_chain = _ptr(RB_PTR);
    uint64_t *chain_ptr[MAX_CHAIN + 1];
    printf("%s = [", label);
    for (int chain_len = 1; chain_len < MAX_CHAIN; ++chain_len) {
        // generate pointers for chain
        for (int k = 0; k < chain_len - 1; ++k) {
            chain_ptr[k] = &rb_chain[CHAIN_OFFSET * (k + 1)];
            if (_ul(chain_ptr[k]) >= RB_PTR + RB_OFFSET + SECRET * RB_STRIDE) {
                UARF_LOG_ERROR("address generation went too far 0x%012lx - 0x%012lx!\n",
                               _ul(chain_ptr[k]),
                               RB_PTR + RB_OFFSET + SECRET * RB_STRIDE);
            }
        }
        chain_ptr[chain_len - 1] = _ptr(RB_PTR + RB_OFFSET + SECRET * RB_STRIDE);
        // shuffle the pointers
        shuffle_array(&chain_ptr[0], chain_len - 1);

        // chain the pointers
        for (int k = 0; k < chain_len - 1; ++k) {
            *(chain_ptr[k]) = _ul(chain_ptr[k + 1]);
        }

        rb_reset();
        for (size_t i = 0; i < ROUNDS; i++) {
            uarf_pi_wrmsr(MSR_PRED_CMD, 1 << MSR_PRED_CMD__IBPB);

            asm volatile(""
                         "call *%2\n\t"
                         :
                         : "d"(dummy_val), "a"(dst_train_ptr), "r"(ctxt->entry_point)
                         : "r8", "memory");

            rb_flush();

            if (set_index != -1) {
                for (int k = 0; k < EVICT_ITERATIONS; ++k) {
                    for (int e = 0; e < eviction_set_size; ++e) {
                        *eviction_sets[set_index * eviction_set_total + e];
                        uarf_lfence();
                    }
                }
            }

            uarf_mfence();

            asm volatile(""
                         "call *%2\n\t"
                         :
                         : "d"(chain_ptr), "a"(dst_ptr), "r"(ctxt->entry_point)
                         : "r8", "memory");

            for (volatile size_t i = 0; i < 10000; i++) {
            }
            rb_reload();
        }

        printf("%ld, ", rb_hist[SECRET]);
    }
    printf("]\n");
}

int main(void) {
    uarf_pi_init();
    rb_init();

    void *mem = mmap(NULL, PAGE_1G, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MFD_HUGE_2MB, -1, 0);
    if (mem == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map 1G of 2MB pages\n");
        return 1;
    }
    // make memory mapped and varying contents to ensure that pages are not combined
    for (uint64_t offset = 0; offset < PAGE_1G; offset += PAGE_4K) {
        *((volatile uint64_t *) (_ul(mem) + offset)) = offset;
    }

    UarfStub stub_src = uarf_stub_init();
    UarfStub stub_victim_dst = uarf_stub_init();
    UarfStub stub_train_dst = uarf_stub_init();
    UarfJitaCtxt jita_src = uarf_jita_init();
    UarfJitaCtxt jita_victim_dst = uarf_jita_init();
    UarfJitaCtxt jita_train_dst = uarf_jita_init();

    uarf_jita_push_psnip(&jita_src, &psnip_src);
    uarf_jita_push_psnip(&jita_victim_dst, &psnip_victim_dst);
    uarf_jita_push_psnip(&jita_train_dst, &psnip_train_dst);

    uarf_jita_allocate(&jita_src, &stub_src, HVA_SRC);
    uarf_jita_allocate(&jita_victim_dst, &stub_victim_dst, HVA_DST + 0x6000);
    uarf_jita_allocate(&jita_train_dst, &stub_train_dst, HVA_DST);

    uint64_t entry_point = stub_src.addr;

    UARF_LOG_INFO("Build eviction sets\n");
    if (!build_l1_sets(_ul(mem), l1_sets)) {
        UARF_LOG_ERROR("Failed to build L1 eviction sets!\n");
        exit(1);
    }
    if (!build_l2_sets(_ul(mem), l2_sets)) {
        UARF_LOG_ERROR("Failed to build L3 eviction sets!\n");
        exit(1);
    }

    for (int i = 0; i < MAX_CHAIN - 1; ++i) {
        dummy_val[i] = _ul(&dummy_val[i + 1]);
    }

    dst_ptr[1] = _ul(stub_victim_dst.addr);
    dst_train_ptr[1] = _ul(stub_train_dst.addr);

    actxt_t ctxt = {.entry_point = entry_point};

    // measure the speculation window sizes for the different cache levels
    // no eviction means the target should stay in L1
    measure_window_size(&ctxt, NULL, 0, 0, 0, L1_THRESH, "y_l1_arr");
    // evict the target from L1 such that it should be in L2 still
    measure_window_size(&ctxt, &l1_sets[0][0], L1_SETS, L1_SET_SIZE, L1_SET_SIZE,
                        L2_THRESH, "y_l2_arr");
    // evict the target from L2 such that it will only be in L3
    measure_window_size(&ctxt, &l2_sets[0][0], L2_SETS, L2_EVICTION_SIZE, L2_1GB_SET_SIZE,
                        L3_THRESH, "y_l3_arr");
    // evict the target from L3 such that it should come from memory
    measure_window_size(&ctxt, &l2_sets[0][0], L2_SETS, L2_1GB_SET_SIZE, L2_1GB_SET_SIZE,
                        RAM_THRESH, "y_ram_arr");

    return 0;
}
