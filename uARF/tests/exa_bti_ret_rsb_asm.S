#include "psnip.h"
#include "asm-macros.h"
#include "spec_lib.h"

.section .note.GNU-stack,"",@progbits

UARF_SNIP_START rogue_ret
   addq $8, %rsp
   clflush (%rsp)
   mfence
   lfence
   ret
UARF_SNIP_END rogue_ret
