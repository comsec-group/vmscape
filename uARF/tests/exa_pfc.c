/**
 * Play with performance counters and show how we can interact with them.
 */

#include "jita.h"
#include "lib.h"
#include "pfc.h"
#include "pfc_amd.h"
#include "spec_lib.h"
#include "test.h"

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_TEST
#endif

static void func1_loop(void) {
    volatile uint64_t a = 5;
    for (size_t i = 0; i < 10; i++) {
        a *= 3;
    }

    *(volatile uint64_t *) &a;
}

UARF_TEST_CASE(read) {
    UarfPfc pfc;
    uarf_pfc_init(&pfc, UARF_AMD_EX_RET_INSTR);

    uint64_t start;
    read(pfc.fd, &start, 8);

    func1_loop();

    uint64_t end;
    read(pfc.fd, &end, 8);

    printf("%lu\n", end - start);

    uarf_pfc_deinit(&pfc);
    UARF_TEST_PASS();
}

UARF_TEST_CASE(rdpmc) {
    UarfPfc pfc;
    uarf_pfc_init(&pfc, UARF_AMD_EX_RET_INSTR);

    uint64_t start = uarf_pfc_read(&pfc);

    func1_loop();

    uint64_t end = uarf_pfc_read(&pfc);

    printf("%lu\n", end - start);

    uarf_pfc_deinit(&pfc);
    UARF_TEST_PASS();
}

UARF_TEST_CASE(pm) {
    UarfPm measure;

    // uarf_pm_init(&measure, AMD_EX_RET_INSTR);
    uarf_pm_init(&measure, UARF_AMD_EX_RET_BRN_IND_MISP);

    uarf_mfence();
    uarf_lfence();
    uarf_pm_start(&measure);
    uarf_pm_stop(&measure);

    printf("%lu\n", uarf_pm_get(&measure));

    uarf_pm_reset(&measure);
    uarf_mfence();
    uarf_lfence();
    uarf_pm_start(&measure);
    uarf_pm_stop(&measure);

    printf("%lu\n", uarf_pm_get(&measure));

    uarf_pm_deinit(&measure);

    UARF_TEST_PASS();
}

UARF_TEST_CASE(pmg) {
    UarfPmg pmg;

    UARF_TEST_PASS();
}

uarf_psnip_declare(rdpmc, psnip_rdpmc);
uarf_psnip_declare_define(psnip_ret, "ret\n\t");

uarf_psnip_declare_define(psnip_counter_init, "movq $0, %rdi\n\t");
uarf_psnip_declare_define(psnip_counter_inc, "inc %rdi\n\t");
uarf_psnip_declare_define(psnip_counter_jmp, "int3\n\t"
                                             "int3\n\t"
                                             "cmp $5, %rdi\n\t"
                                             "je .+16\n\t");

uarf_psnip_declare_define(psnip_reg_ind_br, "lea return_here1(%rip), %rsi\n\t"
                                            "jmp *%rsi\n\t"
                                            "return_here1:\n\t");

uarf_psnip_declare_define(psnip_mem_ind_br, "lea return_here2(%rip), %rsi\n\t"
                                            "pushq %rsi\n\t"
                                            "jmp *(%rsp)\n\t"
                                            "return_here2:\n\t"
                                            "popq %rsi\n\t");

UARF_TEST_CASE(raw_asm) {
    UarfPfc pfc1;
    UarfPfc pfc2;
    UarfPfc pfc3;

    uarf_pfc_init(&pfc1, UARF_AMD_EX_RET_BRN_IND_MISP);
    uarf_pfc_init(&pfc2, UARF_AMD_EX_RET_IND_BRCH_INSTR);
    // uarf_pfc_init(&pfc3, UARF_AMD_EX_RET_INSTR);

    UarfJitaCtxt jita = uarf_jita_init();
    UarfStub stub = uarf_stub_init();

    // We actually only need the stacks it contains
    UarfSpecData data;
    uarf_cstack_reset(&data.ustack);
    uarf_cstack_reset(&data.istack);
    uarf_cstack_reset(&data.ostack);

    // Push PFC indexes to the input stack
    // Start measure
    uarf_cstack_push(&data.istack, pfc1.index);
    uarf_cstack_push(&data.istack, pfc2.index);
    // uarf_cstack_push(&data.istack, pfc3.index);

    // Stop measure
    uarf_cstack_push(&data.istack, pfc1.index);
    uarf_cstack_push(&data.istack, pfc2.index);
    // uarf_cstack_push(&data.istack, pfc3.index);

    // UARF_TEST_ASSERT(data.ustack.index == 0);
    // UARF_TEST_ASSERT(data.istack.index == 6);
    // UARF_TEST_ASSERT(data.ostack.index == 0);

    uarf_jita_push_psnip(&jita, &psnip_counter_init);

    // Start measure
    uarf_jita_push_psnip(&jita, &psnip_rdpmc);
    uarf_jita_push_psnip(&jita, &psnip_rdpmc);
    // uarf_jita_push_psnip(&jita, &psnip_rdpmc);

    uarf_jita_push_vsnip_fill_nop(&jita, 64);

    // Measured section
    uarf_jita_push_psnip(&jita, &psnip_reg_ind_br);
    uarf_jita_push_psnip(&jita, &psnip_mem_ind_br);

    uarf_jita_push_psnip(&jita, &psnip_counter_inc);
    uarf_jita_push_psnip(&jita, &psnip_counter_jmp);

    uarf_jita_push_vsnip_jmp_near_rel(&jita, -32, false);

    uarf_jita_push_vsnip_fill_nop(&jita, 64);

    // Stop measure
    uarf_jita_push_psnip(&jita, &psnip_rdpmc);
    uarf_jita_push_psnip(&jita, &psnip_rdpmc);
    // uarf_jita_push_psnip(&jita, &psnip_rdpmc);

    uarf_jita_push_psnip(&jita, &psnip_ret);

    uarf_jita_allocate(&jita, &stub, uarf_rand47());
    data.spec_prim_p = stub.addr;

    uarf_run_spec(&data);

    // UARF_TEST_ASSERT(data.ustack.index == 0);
    // UARF_TEST_ASSERT(data.istack.index == 0);
    // UARF_TEST_ASSERT(data.ostack.index == 12);

    // Get counter values
    // uint64_t pfc3_end_lo = uarf_cstack_pop(&data.ostack);
    // uint64_t pfc3_end_hi = uarf_cstack_pop(&data.ostack);
    uint64_t pfc2_end_lo = uarf_cstack_pop(&data.ostack);
    uint64_t pfc2_end_hi = uarf_cstack_pop(&data.ostack);
    uint64_t pfc1_end_lo = uarf_cstack_pop(&data.ostack);
    uint64_t pfc1_end_hi = uarf_cstack_pop(&data.ostack);

    // uint64_t pfc3_start_lo = uarf_cstack_pop(&data.ostack);
    // uint64_t pfc3_start_hi = uarf_cstack_pop(&data.ostack);
    uint64_t pfc2_start_lo = uarf_cstack_pop(&data.ostack);
    uint64_t pfc2_start_hi = uarf_cstack_pop(&data.ostack);
    uint64_t pfc1_start_lo = uarf_cstack_pop(&data.ostack);
    uint64_t pfc1_start_hi = uarf_cstack_pop(&data.ostack);

    UARF_TEST_ASSERT(data.ustack.index == 0);
    UARF_TEST_ASSERT(data.istack.index == 0);
    UARF_TEST_ASSERT(data.ostack.index == 0);

    uint64_t pfc1_count = uarf_pm_transform_raw1(&pfc1, pfc1_end_lo, pfc1_end_hi) -
                          uarf_pm_transform_raw1(&pfc1, pfc1_start_lo, pfc1_start_hi);

    uint64_t pfc2_count = uarf_pm_transform_raw1(&pfc2, pfc2_end_lo, pfc2_end_hi) -
                          uarf_pm_transform_raw1(&pfc2, pfc2_start_lo, pfc2_start_hi);

    // uint64_t pfc3_count = uarf_pm_transform_raw1(&pfc3, pfc3_end_lo, pfc3_end_hi) -
    //                       uarf_pm_transform_raw1(&pfc3, pfc3_start_lo, pfc3_start_hi);

    printf("pfc1: %lu\n", pfc1_count);
    printf("pfc2: %lu\n", pfc2_count);
    // printf("pfc3: %lu\n", pfc3_count);

    UARF_TEST_PASS();
}

UARF_TEST_SUITE() {
    UARF_TEST_RUN_CASE(read);
    UARF_TEST_RUN_CASE(rdpmc);
    UARF_TEST_RUN_CASE(pm);
    UARF_TEST_RUN_CASE(pmg);
    UARF_TEST_RUN_CASE(raw_asm);
    return 0;
}
