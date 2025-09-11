#include "asm-macros.h"
#include "page.h"
#include "psnip.h"
#include "spec_lib.h"

# Prevent linker warning: "missing .note.GNU-stack section implies executable stack"
.section .note.GNU-stack,"",@progbits

UARF_SNIP_START src_call_ind_reg
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    movq $0, %rdx                                       // SIZE: 7
    clflush (%rcx)
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    movq (%r8), %r9                                     // SIZE: 4
    # clflush (%r8)                                       // SIZE: 4
    # clflush (%r9)                                       // SIZE: 4
    call *%r9                                           // SIZE: 3
    ret
    int3
UARF_SNIP_END src_call_ind_reg

UARF_SNIP_START src_call_ind_reg_2
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    subq $8, %r8
    clflush 0x8(%r8)                                       // SIZE: 4
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    movq $0, %rdx                                       // SIZE: 7
    call *0x8(%r8)                                         // SIZE: 3
    ret
    int3
UARF_SNIP_END src_call_ind_reg_2
