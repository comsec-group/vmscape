#include "spec_lib.h"
#include <stdlib.h>

UarfHistory uarf_get_randomized_history(void) {
    return (UarfHistory) {
        .hist[0] = random(),
        .hist[1] = random(),
    };
}

// Do not inline, such that we ensure it is "paged"
void uarf_run_spec(void *arg) {
    UarfSpecData *data = (UarfSpecData *) arg;

    asm volatile("lea return_here%=, %%rax\n\t"
                 "pushq %%rax\n\t"
                 "jmp *%0\n\t"
                 "return_here%=:\n\t" ::"r"(data->spec_prim_p),
                 "c"(data)
                 : "rax", "rdx", "rdi", "rsi", "r8", "memory");
}
