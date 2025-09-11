/**
 * JITA, pstubs and vstubs
 *
 * Tests the JITA setup, which is itself based on pstubs and vstubs.
 */

#include "compiler.h"
#include "jita.h"
#include "lib.h"
#include "log.h"
#include "psnip.h"
#include "stub.h"
#include "test.h"
#include "utils.h"
#include "vsnip.h"

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_TEST
#endif

#define ADDR 0x0000701100001000ul

// Declare all used snippets
uarf_psnip_declare(jita_inc, psnip_inc);
uarf_psnip_declare(jita_dec, psnip_dec);
uarf_psnip_declare(jita_jump, psnip_jump);
uarf_psnip_declare(jita_ret_val, psnip_ret_val);

UarfStub stub1;

UarfJitaCtxt jita_inc3;
UarfJitaCtxt jita_get_inc3;

// Use global jita that has been allocated to a global stub
UARF_TEST_CASE(globally_allocated_jita) {

    int (*a)(int) = (int (*)(int)) stub1.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 8);
    UARF_TEST_PASS();
}

// Use a global jita and allocate to local stub
UARF_TEST_CASE(locally_allocated_jita) {

    UarfStub local_stub = uarf_stub_init();
    uarf_jita_allocate(&jita_get_inc3, &local_stub, uarf_rand47());
    UARF_TEST_ASSERT(local_stub.size > 0);

    int (*a)(int) = (int (*)(int)) local_stub.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 8);

    uarf_jita_deallocate(&jita_get_inc3, &local_stub);

    UARF_TEST_PASS();
}

// Local jita
UARF_TEST_CASE(local_jita) {

    UarfJitaCtxt ctxt = uarf_jita_init();
    UarfStub local_stub = uarf_stub_init();

    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_psnip(&ctxt, &psnip_ret_val);

    uarf_jita_allocate(&ctxt, &local_stub, uarf_rand47());

    int (*a)(int) = (int (*)(int)) local_stub.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 8);

    uarf_jita_deallocate(&ctxt, &local_stub);

    UARF_TEST_PASS();
}

// Clone global jita and extend locally.
UARF_TEST_CASE(global_jita_clone_local) {

    UarfJitaCtxt ctxt = uarf_jita_init();
    UarfStub local_stub = uarf_stub_init();

    uarf_jita_clone(&jita_inc3, &ctxt);

    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_psnip(&ctxt, &psnip_jump);
    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_psnip(&ctxt, &psnip_jump);
    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_psnip(&ctxt, &psnip_jump);
    uarf_jita_push_psnip(&ctxt, &psnip_ret_val);

    uarf_jita_allocate(&ctxt, &local_stub, uarf_rand47());

    int (*a)(int) = (int (*)(int)) local_stub.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 11);

    uarf_jita_deallocate(&ctxt, &local_stub);

    UARF_TEST_PASS();
}

// Test vsnip_dump_stub
UARF_TEST_CASE(vsnip_dump_stub) {

    UarfJitaCtxt ctxt = uarf_jita_init();
    UarfStub local_stub = uarf_stub_init();
    UarfStub dump_stub = uarf_stub_init();

    uarf_jita_clone(&jita_get_inc3, &ctxt);
    uarf_jita_push_vsnip_dump_stub(&ctxt, &dump_stub);
    uarf_jita_allocate(&ctxt, &local_stub, ALIGN_UP(uarf_rand47(), PAGE_SIZE));
    UARF_TEST_ASSERT(local_stub.base_addr == dump_stub.base_addr);
    UARF_TEST_ASSERT(local_stub.size == dump_stub.size);
    UARF_TEST_ASSERT(local_stub.addr == dump_stub.addr);
    UARF_TEST_ASSERT(local_stub.end_addr == dump_stub.end_addr);
    uarf_jita_deallocate(&jita_get_inc3, &local_stub);

    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_allocate(&ctxt, &local_stub, uarf_rand47());
    UARF_TEST_ASSERT(local_stub.base_addr == dump_stub.base_addr);
    UARF_TEST_ASSERT(local_stub.size == dump_stub.size);
    UARF_TEST_ASSERT(local_stub.addr == dump_stub.addr);
    UARF_TEST_ASSERT(local_stub.end_addr ==
                     dump_stub.end_addr + uarf_psnip_size(&psnip_inc));
    uarf_jita_deallocate(&jita_get_inc3, &local_stub);

    UARF_TEST_PASS();
}

// Test vsnip_aligned and vsnip_assert_align
// Not checking for false negatives of vsnip_aligned
UARF_TEST_CASE_ARG(vsnip_align, arg) {
    uint64_t alignment = _ul(arg);

    UarfJitaCtxt ctxt = uarf_jita_init();
    UarfStub local_stub = uarf_stub_init();
    UarfStub dump_stub = uarf_stub_init();

    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_vsnip_align(&ctxt, alignment);
    uarf_jita_push_vsnip_assert_align(&ctxt, alignment);
    uarf_jita_push_vsnip_dump_stub(&ctxt, &dump_stub);
    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_psnip(&ctxt, &psnip_ret_val);

    uint64_t addr = uarf_rand47();

    uarf_jita_allocate(&ctxt, &local_stub, addr);

    UARF_TEST_ASSERT(!memcmp(local_stub.ptr, psnip_inc.ptr, uarf_psnip_size(&psnip_inc)));

    uint64_t cur = local_stub.addr + uarf_psnip_size(&psnip_inc);
    while (*(uint8_t *) cur == 0x90) {
        cur++;
    }
    UARF_TEST_ASSERT(ALIGN_UP(cur, alignment) == cur);

    UARF_TEST_ASSERT(cur == dump_stub.end_addr);

    UARF_TEST_ASSERT(!memcmp(_ptr(cur), psnip_inc.ptr, uarf_psnip_size(&psnip_inc)));
    cur += uarf_psnip_size(&psnip_inc);
    UARF_TEST_ASSERT(
        !memcmp(_ptr(cur), psnip_ret_val.ptr, uarf_psnip_size(&psnip_ret_val)));

    int (*a)(int) = (int (*)(int)) local_stub.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 7);

    uarf_jita_deallocate(&ctxt, &local_stub);

    UARF_TEST_PASS();
}

// Aligning an already aligned address does not add more padding
UARF_TEST_CASE(vsnip_align_aligned) {
    UarfJitaCtxt ctxt = uarf_jita_init();
    UarfStub local_stub = uarf_stub_init();
    UarfStub dump_stub1 = uarf_stub_init();
    UarfStub dump_stub2 = uarf_stub_init();

    uarf_jita_clone(&jita_get_inc3, &ctxt);

    uarf_jita_push_vsnip_align(&ctxt, 8);
    uarf_jita_push_vsnip_dump_stub(&ctxt, &dump_stub1);
    uarf_jita_push_vsnip_align(&ctxt, 8);
    uarf_jita_push_vsnip_dump_stub(&ctxt, &dump_stub2);

    uarf_jita_push_psnip(&ctxt, &psnip_inc);

    uarf_jita_allocate(&ctxt, &local_stub, uarf_rand47());
    UARF_TEST_ASSERT(dump_stub1.base_addr == dump_stub2.base_addr);
    UARF_TEST_ASSERT(dump_stub1.addr == dump_stub2.addr);
    UARF_TEST_ASSERT(dump_stub1.end_addr == dump_stub2.end_addr);
    UARF_TEST_ASSERT(dump_stub1.size == dump_stub2.size);

    uarf_jita_deallocate(&ctxt, &local_stub);

    UARF_TEST_PASS();
}

// Test vsnip_jmp_near_abs
UARF_TEST_CASE(vsnip_jmp_near_abs) {
    UarfJitaCtxt jmp_ctxt = uarf_jita_init();
    UarfJitaCtxt target_ctxt = uarf_jita_init();

    UarfStub jmp_stub = uarf_stub_init();
    UarfStub target_stub = uarf_stub_init();

    uint64_t jmp_src_addr = uarf_rand47();
    uint64_t jmp_target_addr = jmp_src_addr ^ (rand() & 0xFFFFFF);
    UARF_TEST_ASSERT(ALIGN_DOWN(jmp_target_addr, PAGE_SIZE) >=
                     ALIGN_DOWN(jmp_src_addr, PAGE_SIZE));

    uarf_jita_push_psnip(&target_ctxt, &psnip_inc);
    uarf_jita_push_psnip(&target_ctxt, &psnip_ret_val);
    uarf_jita_push_vsnip_jmp_near_abs(&jmp_ctxt, jmp_target_addr);
    uarf_jita_push_psnip(&jmp_ctxt, &psnip_dec); // Must not change value

    uarf_jita_allocate(&jmp_ctxt, &jmp_stub, jmp_src_addr);
    uarf_jita_allocate(&target_ctxt, &target_stub, jmp_target_addr);

    int (*a)(int) = (int (*)(int)) jmp_stub.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 6);

    uarf_jita_deallocate(&jmp_ctxt, &jmp_stub);
    uarf_jita_deallocate(&target_ctxt, &target_stub);

    UARF_TEST_PASS();
}

// Test vsnip_jmp_near_rel having the offset be inclusive
UARF_TEST_CASE(vsnip_jmp_near_rel_inclusive) {
    UarfJitaCtxt jmp_ctxt = uarf_jita_init();
    UarfJitaCtxt target_ctxt = uarf_jita_init();

    UarfStub jmp_stub = uarf_stub_init();
    UarfStub target_stub = uarf_stub_init();
    UarfStub jmp_dump = uarf_stub_init();

    uint64_t jmp_src_addr = uarf_rand47();
    uint32_t offset = rand() & 0xFFFFFF;
    uint64_t jmp_target_addr = jmp_src_addr + offset;
    UARF_TEST_ASSERT(ALIGN_DOWN(jmp_target_addr, PAGE_SIZE) >=
                     ALIGN_DOWN(jmp_src_addr, PAGE_SIZE));

    uarf_jita_push_psnip(&target_ctxt, &psnip_inc);
    uarf_jita_push_psnip(&target_ctxt, &psnip_ret_val);
    uarf_jita_push_vsnip_dump_stub(&jmp_ctxt, &jmp_dump);
    uarf_jita_push_vsnip_jmp_near_rel(&jmp_ctxt, offset, true);
    uarf_jita_push_psnip(&jmp_ctxt, &psnip_dec); // Must not change value

    uarf_jita_allocate(&jmp_ctxt, &jmp_stub, jmp_src_addr);
    uarf_jita_allocate(&target_ctxt, &target_stub, jmp_target_addr);

    UARF_TEST_ASSERT(jmp_dump.end_addr + offset == target_stub.addr);

    int (*a)(int) = (int (*)(int)) jmp_stub.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 6);

    uarf_jita_deallocate(&jmp_ctxt, &jmp_stub);
    uarf_jita_deallocate(&target_ctxt, &target_stub);

    UARF_TEST_PASS();
}

// Test vsnip_jmp_near_rel having the offset be exclusive
UARF_TEST_CASE(vsnip_jmp_near_rel_exclusive) {
    UarfJitaCtxt jmp_ctxt = uarf_jita_init();
    UarfJitaCtxt target_ctxt = uarf_jita_init();

    UarfStub jmp_stub = uarf_stub_init();
    UarfStub target_stub = uarf_stub_init();
    UarfStub jmp_dump = uarf_stub_init();

    uint64_t jmp_src_addr = uarf_rand47();
    uint32_t offset = rand() & 0xFFFFFF;
    uint64_t jmp_target_addr = jmp_src_addr + offset + 5;
    UARF_TEST_ASSERT(ALIGN_DOWN(jmp_target_addr, PAGE_SIZE) >=
                     ALIGN_DOWN(jmp_src_addr, PAGE_SIZE));

    UARF_LOG_DEBUG("offset %u\n", offset);

    uarf_jita_push_psnip(&target_ctxt, &psnip_inc);
    uarf_jita_push_psnip(&target_ctxt, &psnip_ret_val);
    uarf_jita_push_vsnip_jmp_near_rel(&jmp_ctxt, offset, false);
    uarf_jita_push_vsnip_dump_stub(&jmp_ctxt, &jmp_dump);
    uarf_jita_push_psnip(&jmp_ctxt, &psnip_dec); // Must not change value

    uarf_jita_allocate(&jmp_ctxt, &jmp_stub, jmp_src_addr);
    uarf_jita_allocate(&target_ctxt, &target_stub, jmp_target_addr);

    UARF_TEST_ASSERT(jmp_dump.end_addr + offset == target_stub.addr);

    int (*a)(int) = (int (*)(int)) jmp_stub.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 6);

    uarf_jita_deallocate(&jmp_ctxt, &jmp_stub);
    uarf_jita_deallocate(&target_ctxt, &target_stub);

    UARF_TEST_PASS();
}

// Test vsnip_fill
UARF_TEST_CASE(vsnip_fill) {
    UarfJitaCtxt ctxt = uarf_jita_init();
    UarfStub stub = uarf_stub_init();
    UarfStub dump_before = uarf_stub_init();
    UarfStub dump_after = uarf_stub_init();

    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_vsnip_dump_stub(&ctxt, &dump_before);
    uarf_jita_push_vsnip_fill_nop(&ctxt, 42);
    uarf_jita_push_vsnip_dump_stub(&ctxt, &dump_after);
    uarf_jita_push_psnip(&ctxt, &psnip_inc);
    uarf_jita_push_psnip(&ctxt, &psnip_ret_val);

    uint64_t addr = uarf_rand47();

    uarf_jita_allocate(&ctxt, &stub, addr);

    // Before is no nop
    UARF_TEST_ASSERT(*(uint8_t *) (dump_before.end_addr - 1) != 0x90);

    // In-between is all nops
    for (size_t i = 0; i < 42; i++) {
        UARF_TEST_ASSERT(*(uint8_t *) (dump_before.end_addr + i) == 0x90);
    }

    // After is no nop
    UARF_TEST_ASSERT(*(uint8_t *) (dump_after.end_addr) != 0x90);
    UARF_TEST_ASSERT(dump_after.end_addr = dump_before.end_addr + 42);

    int (*a)(int) = (int (*)(int)) stub.ptr;
    int var = a(5);

    UARF_TEST_ASSERT(var == 7);

    UARF_TEST_PASS();
}

UARF_TEST_SUITE() {

    uarf_jita_push_psnip(&jita_inc3, &psnip_inc);
    uarf_jita_push_psnip(&jita_inc3, &psnip_inc);
    uarf_jita_push_psnip(&jita_inc3, &psnip_inc);

    uarf_jita_clone(&jita_inc3, &jita_get_inc3);
    uarf_jita_push_psnip(&jita_get_inc3, &psnip_ret_val);

    uarf_jita_allocate(&jita_get_inc3, &stub1, uarf_rand47());

    UARF_TEST_RUN_CASE(globally_allocated_jita);
    UARF_TEST_RUN_CASE(locally_allocated_jita);
    UARF_TEST_RUN_CASE(local_jita);
    UARF_TEST_RUN_CASE(global_jita_clone_local);
    UARF_TEST_RUN_CASE(vsnip_dump_stub);
    UARF_TEST_RUN_CASE_ARG(vsnip_align, _ptr(1));
    UARF_TEST_RUN_CASE_ARG(vsnip_align, _ptr(2));
    UARF_TEST_RUN_CASE_ARG(vsnip_align, _ptr(4));
    UARF_TEST_RUN_CASE_ARG(vsnip_align, _ptr(8));
    UARF_TEST_RUN_CASE_ARG(vsnip_align, _ptr(16));
    UARF_TEST_RUN_CASE(vsnip_align_aligned);
    UARF_TEST_RUN_CASE(vsnip_jmp_near_abs);
    UARF_TEST_RUN_CASE(vsnip_jmp_near_rel_inclusive);
    UARF_TEST_RUN_CASE(vsnip_jmp_near_rel_exclusive);
    UARF_TEST_RUN_CASE(vsnip_fill);

    return 0;
}
