#include "asm-macros.h"
#include "page.h"
#include "psnip.h"

UARF_SNIP_START jita_inc
    inc %rdi
UARF_SNIP_END jita_inc

UARF_SNIP_START jita_dec
    dec %rdi
UARF_SNIP_END jita_dec

UARF_SNIP_START jita_jump
   jmp 1f
   .fill 7, 1, 0x90
1:
   nop
UARF_SNIP_END jita_jump

UARF_SNIP_START jita_ret_val
   mov %rdi, %rax
   ret
UARF_SNIP_END jita_ret_val
