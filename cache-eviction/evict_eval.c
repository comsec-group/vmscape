#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "compiler.h"
#include "lib.h"
#include "log.h"

/* start measure */
static __always_inline uint64_t rb_rdtsc(void) {
    unsigned lo, hi;
    asm volatile("lfence\n\t"
                 "rdtsc\n\t"
                 : "=d"(hi), "=a"(lo));
    return ((uint64_t) hi << 32) | lo;
}

/* stop measure */
static __always_inline uint64_t rb_rdtscp(void) {
    unsigned lo, hi;
    asm volatile("rdtscp\n\t"
                 "lfence\n\t"
                 : "=d"(hi), "=a"(lo)::"ecx");
    return ((uint64_t) hi << 32) | lo;
}

#define PAGE_4K     (4096UL)
#define PAGE_2M     (512 * PAGE_4K)
#define PAGE_1G     (512 * PAGE_2M)
#define PROT_RW     (PROT_READ | PROT_WRITE)
#define PROT_RWX    (PROT_RW | PROT_EXEC)
#define PG_ROUND(n) (((((n) - 1UL) >> 12) + 1) << 12)

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
#define NUM_MEASUREMENTS 16
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
#define RAM_THRESH 300

volatile uint64_t *l2_sets[L2_SETS][L2_1GB_SET_SIZE] = {0};
uint64_t l2_sets_offset = 0;
uint64_t measurements[NUM_MEASUREMENTS];

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
        uint64_t start = rb_rdtsc();
        uarf_lfence();
        *victim_ptr;
        uarf_lfence();
        uint64_t end = rb_rdtscp();
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

int main(int argc, char const *argv[]) {
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

    UARF_LOG_INFO("Build L3 eviction sets\n");
    if (!build_l2_sets(_ul(mem), l2_sets)) {
        UARF_LOG_ERROR("Failed to build L3 eviction sets!\n");
        exit(1);
    }
    else {
        // test L3 eviction
        UARF_LOG_INFO("Test L3 eviction sets\n");
        for (int l2_set = 0; l2_set < L2_SETS; ++l2_set) {
            uint64_t res = measure_eviction(l2_sets[l2_set][0], &l2_sets[l2_set][1],
                                            L2_1GB_SET_SIZE - 1);
            if (res < RAM_THRESH) {
                UARF_LOG_ERROR("L3 set %d broken %lu!\n", l2_set, res);
                exit(2);
            }
        }
        UARF_LOG_INFO("All L3 sets work!\n");
    }

    return 0;
}
