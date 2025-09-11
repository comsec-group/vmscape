/*
 * Library of ASM snippets that are useful for branch predictor code.
 */

##include <toolkit/lib.h>

#include "psnip.h"
#include "asm-macros.h"
#include "flush_reload.h"
#include "spec_lib.h"

# Prevent linker warning: "missing .note.GNU-stack section implies executable stack"
.section .note.GNU-stack,"",@progbits

/*
 * Victim branch source using an indirect call
 * Regs:
 * - RCX: Pointer to SpecData struct
 * Stack:
 * - Return address
 * Clobbers: RDI, RSI, R8
 */
UARF_SNIP_START src_call_ind
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    movq $0, %rdx                                       // SIZE: 7
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    clflush (%r8)                                       // SIZE: 4
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    call *(%r8)                                         // SIZE: 3
    // Push return to next cacheline to prevent overwriting of BTB entry
    .fill 64, 1, 0x90
    ret
    int3
UARF_SNIP_END src_call_ind

UARF_SNIP_START src_call_ind_no_ret
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    movq $0, %rdx                                       // SIZE: 7
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    clflush (%r8)                                       // SIZE: 4
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    call *(%r8)                                         // SIZE: 3
UARF_SNIP_END src_call_ind_no_ret

/*
 * Victim branch source using an indirect jmp
 * Regs:
 * - RCX: Pointer to SpecData struct
 * Stack:
 * - Return address
 * Clobbers: RDI, RSI, R8
 */
UARF_SNIP_START src_jmp_ind
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    movq $0, %rdx                                       // SIZE: 7
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    clflush (%r8)                                       // SIZE: 4
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    jmp *(%r8) // Calls return                          // SIZE: 3
    int3
UARF_SNIP_END src_jmp_ind

UARF_SNIP_START src_jmp_ind_no_ret
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    lea 25(%rip), %rdx                                  // SIZE: 7 Address of end of block (=> return address)
    pushq %rdx                                          // SIZE: 1
    movq $0, %rdx                                       // SIZE: 7
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    clflush (%r8)                                       // SIZE: 4
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    jmp *(%r8) // Calls return                          // SIZE: 3
UARF_SNIP_END src_jmp_ind_no_ret

/*
 * Victim branch source using an return (no RSB underflow or anything)
 * Regs:
 * - RCX: Pointer to SpecData struct
 * Stack:
 * - Return address
 * Clobbers: RDI, RSI, R8
 */
UARF_SNIP_START src_ret
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    movq $0, %rdx                                       // SIZE: 7
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    pushq (%r8)                                         // SIZE: 3
    clflush (%rsp)                                      // SIZE: 4
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    ret // Calls return                                 // SIZE: 1
    int3
UARF_SNIP_END src_ret

UARF_SNIP_START src_ret_no_ret
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    lea 26(%rip), %rdx                                  // SIZE: 7 Address of end of block (=> return address)
    pushq %rdx                                          // SIZE: 1
    movq $0, %rdx                                       // SIZE: 7
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    pushq (%r8)                                         // SIZE: 3
    clflush (%rsp)                                      // SIZE: 4
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    ret                                                 // SIZE: 1
UARF_SNIP_END src_ret_no_ret

/*
 * Victim branch source using an return, utilizing the RSB to make a prediction
 * Regs:
 * - RCX: Pointer to SpecData struct
 * Stack:
 * - Return address
 * Clobbers: RDI, RSI, R8
 */
UARF_SNIP_START src_ret_rsp
    movq UARF_DATA__fr_buf_p(%rcx), %rdi                // SIZE: 4
    movq UARF_DATA__secret(%rcx), %rsi                  // SIZE: 4
    movq $0, %rdx                                       // SIZE: 7
    movq UARF_DATA__spec_dst_p_p(%rcx), %r8             // SIZE: 4
    movq (%r8), %r8
    mfence // Keep here for now. Creates a new BB       // SIZE: 3
    lfence                                              // SIZE: 3
    call *%r8                                           // SIZE: 3
    // Place gadget here
UARF_SNIP_END src_ret_rsp

/*
 * Gadget Code, leaking the secret when executed speculatively
 * Regs:
 * - RDI: Base address of FR buffer
 * - RSI: Secret encoded as offset into FR buffer
 * Stack:
 * - Return Address
 * Clobbers: RDI, RSI, RAX
 */
UARF_SNIP_START dst_gadget
    shlq $FR_STRIDE_BITS, %rsi
    movq (%rdi, %rsi), %rax
    lfence
    ret
    int3
UARF_SNIP_END dst_gadget

/*
 * Gadget Code, determining the size of the speculation windows in terms of memory fetches that can be done
 * Acces FR_BUF[0], uses the return value recursively to index into FR_BUF.
 * Regs:
 * - RDI: Base address of FR buffer
 * - RSI: Secret encoded as offset into FR buffer
 * Stack:
 * - Return Address
 * Clobbers: RDI, RSI, RAX
 */
UARF_SNIP_START dst_gadget_time
    // Access FR_BUF[0]
    movq (%rdi), %rax
    // Access FR_BUF[%rax]
    shlq $FR_STRIDE_BITS, %rax
    movq (%rdi, %rax), %rax
    // Access FR_BUF[%rax]
    shlq $FR_STRIDE_BITS, %rax
    movq (%rdi, %rax), %rax
    // Access FR_BUF[%rax]
    shlq $FR_STRIDE_BITS, %rax
    movq (%rdi, %rax), %rax
    // Access FR_BUF[%rax]
    shlq $FR_STRIDE_BITS, %rax
    movq (%rdi, %rax), %rax
    // Access FR_BUF[%rax]
    shlq $FR_STRIDE_BITS, %rax
    movq (%rdi, %rax), %rax
    // Access FR_BUF[%rax]
    shlq $FR_STRIDE_BITS, %rax
    movq (%rdi, %rax), %rax
    // Access FR_BUF[%rax]
    shlq $FR_STRIDE_BITS, %rax
    movq (%rdi, %rax), %rax
    lfence
    ret
    int3
UARF_SNIP_END dst_gadget_time

/*
 * Gadget Code, leaking the tainted secret when executed speculatively
 * The secret is tained by adding constant i to it
 * Regs:
 * - RDI: Base address of FR buffer
 * - RSI: Secret encoded as an index into FR buffer
 * Stack:
 * - Return Address
 * Clobbers: RDI, RSI, RAX
 */
.macro dst_gadget_i i
    UARF_SNIP_START dst_gadget_\i
        addq $\i, %rsi
        shlq $FR_STRIDE_BITS, %rsi
        movq (%rdi, %rsi), %rax
        lfence
        ret
        int3
    UARF_SNIP_END dst_gadget_\i
.endm

dst_gadget_i 0
dst_gadget_i 1
dst_gadget_i 2
dst_gadget_i 3
dst_gadget_i 4
dst_gadget_i 5
dst_gadget_i 6
dst_gadget_i 7
dst_gadget_i 8
dst_gadget_i 9
dst_gadget_i 10
dst_gadget_i 11
dst_gadget_i 12
dst_gadget_i 13
dst_gadget_i 14
dst_gadget_i 15
dst_gadget_i 16
dst_gadget_i 17
dst_gadget_i 18
dst_gadget_i 19
dst_gadget_i 20
dst_gadget_i 21
dst_gadget_i 22
dst_gadget_i 23
dst_gadget_i 24
dst_gadget_i 25
dst_gadget_i 26
dst_gadget_i 27
dst_gadget_i 28
dst_gadget_i 29
dst_gadget_i 30
dst_gadget_i 31

# Dummy Code
# Stack:
# - Return Address
UARF_SNIP_START dst_dummy
    lfence
    ret
    int3
UARF_SNIP_END dst_dummy

UARF_SNIP_START history
    movq UARF_DATA__hist(%rcx), %rax    // SIZE: 4
    test $0x00000001, %eax          // SIZE: 5
    jz 1f                           // Size: 2
    .skip 0x8, 0x90
    1:
    test $0x00000002, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000004, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000008, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000010, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000020, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000040, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000080, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000100, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000200, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000400, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000800, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00001000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00002000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00004000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00008000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00010000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00020000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00040000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00080000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00100000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00200000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00400000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00800000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x01000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x02000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x04000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x08000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x10000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x20000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x40000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x80000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
// Mid
    movq (UARF_DATA__hist + UARF_DATA__hist_size)(%rcx), %rax
    test $0x00000001, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000002, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000004, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000008, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000010, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000020, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000040, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000080, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000100, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000200, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000400, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00000800, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00001000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00002000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00004000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00008000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00010000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00020000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00040000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00080000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00100000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00200000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00400000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x00800000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x01000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x02000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x04000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x08000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x10000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x20000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x40000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
    test $0x80000000, %eax
    jz 1f
    .skip 0x8, 0x90
    1:
UARF_SNIP_END history

/*
 * Get the index into a custom stack from the data memory.
 *
 * Backup `index_reg` to `scratch_offset` and load `index_offset` into `index_reg`
 */
.macro CSTACK_LOAD_INDEX data_base_reg, index_offset, scratch_offset, index_reg
    movq \index_reg, \scratch_offset(\data_base_reg)
    movq \index_offset(\data_base_reg), \index_reg
.endm

/*
 * Store the index into a custom stack into the data memory.
 *
 * Store `index_reg` in `index_offset` and load `scratch_offset` into `index_reg`
 */
.macro CSTACK_STORE_INDEX data_base_reg, index_offset, scratch_offset, index_reg
    movq \index_reg, \index_offset(\data_base_reg)
    movq \scratch_offset(\data_base_reg), \index_reg
.endm

/*
 * Push `value` (reg or immediate) to a custom stack.
 */
.macro CSTACK_PUSH data_base_reg, stack_offset, index_offset, scratch_offset, index_reg, value
    CSTACK_LOAD_INDEX \data_base_reg, \index_offset, \scratch_offset, \index_reg
    movq \value, \stack_offset(\data_base_reg, \index_reg, 8)
    inc \index_reg
    CSTACK_STORE_INDEX \data_base_reg, \index_offset, \scratch_offset, \index_reg
.endm

/*
 * Pop a value from a custom stack into `reg`
 */
.macro CSTACK_POP data_base_reg, stack_offset, index_offset, scratch_offset, index_reg, reg
    CSTACK_LOAD_INDEX \data_base_reg, \index_offset, \scratch_offset, \index_reg
    dec \index_reg
    movq \stack_offset(\data_base_reg, \index_reg, 8), \reg
    CSTACK_STORE_INDEX \data_base_reg, \index_offset, \scratch_offset, \index_reg
.endm

// User Stack Macros
.macro USTACK_PUSH value, data_base_reg=%rcx, index_reg=%r8
    CSTACK_PUSH \data_base_reg, UARF_USTACK_STACK_OFFSET, UARF_USTACK_INDEX_OFFSET, UARF_USTACK_SCRATCH_OFFSET, \index_reg, \value
.endm

.macro USTACK_POP reg, data_base_reg=%rcx, index_reg=%r8
    CSTACK_POP \data_base_reg, UARF_USTACK_STACK_OFFSET, UARF_USTACK_INDEX_OFFSET, UARF_USTACK_SCRATCH_OFFSET, \index_reg, \reg
.endm

// Input Stack Macros
.macro ISTACK_PUSH value, data_base_reg=%rcx, index_reg=%r8
    CSTACK_PUSH \data_base_reg, UARF_ISTACK_STACK_OFFSET, UARF_ISTACK_INDEX_OFFSET, UARF_ISTACK_SCRATCH_OFFSET, \index_reg, \value
.endm

.macro ISTACK_POP reg, data_base_reg=%rcx, index_reg=%r8
    CSTACK_POP \data_base_reg, UARF_ISTACK_STACK_OFFSET, UARF_ISTACK_INDEX_OFFSET, UARF_ISTACK_SCRATCH_OFFSET, \index_reg, \reg
.endm

// Output Stack Macros
.macro OSTACK_PUSH value, data_base_reg=%rcx, index_reg=%r8
    CSTACK_PUSH \data_base_reg, UARF_OSTACK_STACK_OFFSET, UARF_OSTACK_INDEX_OFFSET, UARF_OSTACK_SCRATCH_OFFSET, \index_reg, \value
.endm

.macro OSTACK_POP reg, data_base_reg=%rcx, index_reg=%r8
    CSTACK_POP \data_base_reg, UARF_OSTACK_STACK_OFFSET, UARF_OSTACK_INDEX_OFFSET, UARF_OSTACK_SCRATCH_OFFSET, \index_reg, \reg
.endm

UARF_SNIP_START rdpmc
    // Switch data base pointer to rsi as we need rcx
    USTACK_PUSH %rsi
    movq %rcx, %rsi

    // Backup registers
    USTACK_PUSH %rdx, %rsi
    USTACK_PUSH %rax, %rsi

    // Get value from input
    ISTACK_POP %rcx, %rsi

    // Zero upper portion as we push 64 for simplicity
    xor %rdx, %rdx
    xor %rax, %rax

    // Read performance counter
    rdpmc

    // Store value to output
    OSTACK_PUSH %rdx, %rsi
    OSTACK_PUSH %rax, %rsi

    // Restore registers
    USTACK_POP %rax, %rsi
    USTACK_POP %rdx, %rsi

    // Restore data base pointer from rsi to rcx
    movq %rsi, %rcx
    USTACK_POP %rsi
UARF_SNIP_END rdpmc
