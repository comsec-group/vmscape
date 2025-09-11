/**
 * Untrain
 *
 * Can we make the BPU forget about the previous branch by executing some nops at that
 * location?
 *
 * No, simply passing over an instruction with a nop does not evict it!
 *
 * TODO: Can we untrain by using a different branch instruction?
 */

#include "flush_reload.h"
#include "jita.h"
#include "kmod/pi.h"
#include "lib.h"
#include "log.h"
#include "spec_lib.h"
#include "test.h"

#include <sys/mman.h>

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_TEST
#endif

uarf_psnip_declare(history, psnip_history);
uarf_psnip_declare(src_jmp_ind, psnip_src_jmp_ind);
uarf_psnip_declare(dst_gadget, psnip_dst_gadget);
uarf_psnip_declare(dst_dummy, psnip_dst_dummy);
uarf_psnip_declare_define(psnip_ret, "ret\n\t");

struct TestCaseData {
    uint32_t seed;
    uint32_t num_cands;
    uint32_t num_rounds;
    uint32_t num_train_rounds;
    UarfJitaCtxt *jita_main;
    UarfJitaCtxt *jita_untrain;
    UarfJitaCtxt *jita_gadget;
    UarfJitaCtxt *jita_dummy;
    bool match_history;
    bool untrain;
};

UARF_TEST_CASE_ARG(basic, arg) {
    struct TestCaseData *data = (struct TestCaseData *) arg;
    srand(data->seed);

    // struct FrConfig fr = fr_init(8, 6, (size_t[]){0, 1, 2, 3, 5, 10});
    UarfFrConfig fr = uarf_fr_init(8, 1, NULL);

    UarfStub stub_main = uarf_stub_init();
    UarfStub stub_gadget = uarf_stub_init();
    UarfStub stub_dummy = uarf_stub_init();

    uarf_ibpb();

    uarf_fr_reset(&fr);

    for (size_t c = 0; c < data->num_cands; c++) {
        uint64_t main_addr = uarf_rand47();
        uarf_jita_allocate(data->jita_main, &stub_main, main_addr);
        uarf_jita_allocate(data->jita_gadget, &stub_gadget, uarf_rand47());
        uarf_jita_allocate(data->jita_dummy, &stub_dummy, uarf_rand47());

        UarfHistory h1 = uarf_get_randomized_history();
        UarfHistory h2 = data->match_history ? h1 : uarf_get_randomized_history();

        UarfSpecData train_data = {
            .spec_prim_p = stub_main.addr,
            .spec_dst_p_p = _ul(&stub_gadget.addr),
            .fr_buf_p = fr.buf2.addr,
            .secret = 0,
            .hist = h1,
        };

        UarfSpecData signal_data = {
            .spec_prim_p = stub_main.addr,
            .spec_dst_p_p = _ul(&stub_dummy.addr),
            .fr_buf_p = fr.buf.addr,
            .secret = 1,
            .hist = h2,
        };

        for (size_t r = 0; r < data->num_rounds; r++) {

            if (data->untrain) {
                uarf_jita_deallocate(data->jita_main, &stub_main);
                uarf_jita_allocate(data->jita_untrain, &stub_main, main_addr);
                for (size_t t = 0; t < 1000; t++) {
                    asm("untrain:\n\t");
                    asm volatile("lea return_here%=, %%rax\n\t"
                                 "pushq %%rax\n\t"
                                 "jmp *%0\n\t"
                                 "return_here%=:\n\t" ::"r"(train_data.spec_prim_p),
                                 "c"(&train_data)
                                 : "rax", "rdx", "rdi", "rsi", "r8", "memory");
                }
                uarf_jita_deallocate(data->jita_untrain, &stub_main);
                uarf_jita_allocate(data->jita_main, &stub_main, main_addr);
                // uarf_ibpb();
            }

            for (size_t t = 0; t < data->num_train_rounds; t++) {
                asm("train:\n\t");
                asm volatile("lea return_here%=, %%rax\n\t"
                             "pushq %%rax\n\t"
                             "jmp *%0\n\t"
                             "return_here%=:\n\t" ::"r"(train_data.spec_prim_p),
                             "c"(&train_data)
                             : "rax", "rdx", "rdi", "rsi", "r8", "memory");
            }

            // uarf_assert(!mprotect(stub_gadget.base_ptr, stub_gadget.size, PROT_READ |
            // PROT_WRITE));
            uarf_fr_flush(&fr);
            uarf_clflush_spec_dst(&signal_data);
            // uarf_invlpg_spec_dst(&signal_data);
            uarf_prefetcht0(&train_data);

            // TODO: disable interrupts and preemption
            asm("signal:\n\t");
            asm volatile("lea return_here%=, %%rax\n\t"
                         "pushq %%rax\n\t"
                         "jmp *%0\n\t"
                         "return_here%=:\n\t" ::"r"(signal_data.spec_prim_p),
                         "c"(&signal_data)
                         : "rax", "rdx", "rdi", "rsi", "r8", "memory");

            uarf_fr_reload_binned(&fr, r);
            // uarf_assert(!mprotect(stub_gadget.base_ptr, stub_gadget.size, PROT_READ |
            // PROT_WRITE | PROT_EXEC));
        }
        uarf_jita_deallocate(data->jita_main, &stub_main);
        uarf_jita_deallocate(data->jita_gadget, &stub_gadget);
        uarf_jita_deallocate(data->jita_dummy, &stub_dummy);
    }

    UARF_LOG_INFO("Fr Buffer\n");
    uarf_fr_print(&fr);

    uarf_fr_deinit(&fr);

    UARF_TEST_PASS();
}

static struct TestCaseData data1;
static struct TestCaseData data2;
static struct TestCaseData data3;
static struct TestCaseData data4;

UARF_TEST_SUITE() {
    uint32_t seed = uarf_get_seed();
    UARF_LOG_INFO("Using seed: %u\n", seed);
    uarf_pi_init();

    UarfJitaCtxt jita_main = uarf_jita_init();
    UarfJitaCtxt jita_main_untrain = uarf_jita_init();
    UarfJitaCtxt jita_gadget = uarf_jita_init();
    UarfJitaCtxt jita_dummy = uarf_jita_init();

    uarf_jita_push_psnip(&jita_main, &psnip_history);
    uarf_jita_push_psnip(&jita_main, &psnip_history);
    uarf_jita_push_psnip(&jita_main, &psnip_history);
    uarf_jita_push_psnip(&jita_main, &psnip_history);
    uarf_jita_push_psnip(&jita_main, &psnip_history);

    uarf_jita_clone(&jita_main, &jita_main_untrain);
    uarf_jita_push_vsnip_fill_nop(&jita_main_untrain, 48);
    uarf_jita_push_psnip(&jita_main_untrain, &psnip_ret);

    uarf_jita_push_psnip(&jita_main, &psnip_src_jmp_ind);

    uarf_jita_push_psnip(&jita_gadget, &psnip_dst_gadget);
    uarf_jita_push_psnip(&jita_dummy, &psnip_dst_dummy);

    data1 = (struct TestCaseData) {
        .seed = seed++,
        .num_cands = 100,
        .num_rounds = 10,
        .num_train_rounds = 1,
        .jita_main = &jita_main,
        .jita_untrain = &jita_main_untrain,
        .jita_gadget = &jita_gadget,
        .jita_dummy = &jita_dummy,
        .match_history = true,
        .untrain = false,
    };

    data2 = (struct TestCaseData) {
        .seed = seed++,
        .num_cands = 100,
        .num_rounds = 10,
        .num_train_rounds = 1,
        .jita_main = &jita_main,
        .jita_untrain = &jita_main_untrain,
        .jita_gadget = &jita_gadget,
        .jita_dummy = &jita_dummy,
        .match_history = false,
        .untrain = false,
    };

    data3 = (struct TestCaseData) {
        .seed = seed++,
        .num_cands = 100,
        .num_rounds = 10,
        .num_train_rounds = 1,
        .jita_main = &jita_main,
        .jita_untrain = &jita_main_untrain,
        .jita_gadget = &jita_gadget,
        .jita_dummy = &jita_dummy,
        .match_history = true,
        .untrain = true,
    };

    data4 = (struct TestCaseData) {
        .seed = seed++,
        .num_cands = 100,
        .num_rounds = 10,
        .num_train_rounds = 1,
        .jita_main = &jita_main,
        .jita_untrain = &jita_main_untrain,
        .jita_gadget = &jita_gadget,
        .jita_dummy = &jita_dummy,
        .match_history = false,
        .untrain = true,
    };

    UARF_TEST_RUN_CASE_ARG(basic, &data1);
    UARF_TEST_RUN_CASE_ARG(basic, &data2);
    UARF_TEST_RUN_CASE_ARG(basic, &data3);
    UARF_TEST_RUN_CASE_ARG(basic, &data4);

    uarf_pi_deinit();

    return 0;
}
