/**
 * Evict L3 but not L1
 *
 * Can we evict L3, but keep something else in L1?
 *
 * No, somehow it is not working. Maybe due to the prefetcher accessing stuff of CLs that
 * are not part of our ES.
 */

#include "cache.h"
#include "evict.h"
#include "lib.h"
#include "log.h"
#include "mem.h"
#include "page.h"
#include "test.h"
#include <stdbool.h>

uint64_t victim;
uint64_t victim_l2_set;

bool cand_different_l2_set(EsElem *elem) {
    uarf_assert(!mlock(elem->data, sizeof(EsElem)));
    uint64_t set = uarf_get_l2_set(uarf_va_to_pa(_ul(elem->data), 0));
    return set != victim_l2_set && set != victim_l2_set + 1 && set != victim_l2_set - 1 &&
           set != victim_l2_set + 2 && set != victim_l2_set - 2 &&
           set != victim_l2_set + 3 && set != victim_l2_set - 3 &&
           set != victim_l2_set + 4 && set != victim_l2_set - 4 &&
           set != victim_l2_set + 5 && set != victim_l2_set - 5 &&
           set != victim_l2_set + 6 && set != victim_l2_set - 6;
}

UARF_TEST_CASE(basic) {

    // uarf_pi_init();
    // uarf_wrmsr_user(0xc0000108, 47);

    void *victim_page = uarf_alloc_random_page();
    uarf_assert(!mlock(_ptr(victim_page), PAGE_SIZE));

    victim = _ul(victim_page) + (uarf_rand47() & (PAGE_SIZE - 1));
    victim_l2_set = uarf_get_l2_set(uarf_va_to_pa(victim, 0));
    UARF_LOG_INFO("Victim: 0x%lx, L2 set: %lu\n", victim, victim_l2_set);

    const size_t NUM_CANDS = 5;

    uint64_t cands[NUM_CANDS];

    for (size_t i = 0; i < NUM_CANDS; i++) {
        void *p = uarf_alloc_random_page();
        uarf_assert(!mlock(p, PAGE_SIZE));
        uint64_t cand_set;
        do {
            cands[i] = _ul(p) + (uarf_rand47() & (PAGE_SIZE - 1));
            cand_set = uarf_get_l2_set(uarf_va_to_pa(cands[i], 0));
        } while (cand_set == victim_l2_set);
        printf("Cand: 0x%lx, L2 set: %lu\n", cands[i], cand_set);
    }

    UARF_LOG_DEBUG("Init Es\n");
    Es *es;
    uarf_es_init(&es, 1000000);

    UARF_LOG_DEBUG("Filter ES\n");
    uarf_dll_filter(es, cand_different_l2_set);

    // uarf_dll_for_each(es, elem) {
    //     if (elem->type == UARF_DLL_NODE_TYPE_NORMAL) {
    //         uarf_assert(uarf_get_l2_set(uarf_va_to_pa(_ul(elem->data), 0)) !=
    //                     victim_l2_set);
    //         uarf_assert(uarf_get_l2_set(uarf_va_to_pa(_ul(elem->data), 0)) !=
    //                     victim_l2_set - 1);
    //         uarf_assert(uarf_get_l2_set(uarf_va_to_pa(_ul(elem->data), 0)) !=
    //                     victim_l2_set - 2);
    //     }
    // }

    UARF_LOG_DEBUG("ES size: %lu\n", uarf_dll_size(es));

    UARF_LOG_INFO("Access time before:\n");

    *(volatile uint64_t *) victim;
    UARF_LOG_INFO("\tVictim: %lu\n", uarf_get_access_time_a(_ptr(victim)));

    for (size_t i = 0; i < NUM_CANDS; i++) {
        *(volatile uint64_t *) cands[i];
        uarf_mfence();
        UARF_LOG_INFO("\tCand %lu: %lu\n", i, uarf_get_access_time_a(_ptr(cands[i])));
    }

    UARF_LOG_DEBUG("Evict...\n");
    // uarf_es_access_local(es, 1);
    uarf_es_access_fbf(es, 1);

    UARF_LOG_INFO("Access time after:\n");

    for (size_t i = 0; i < NUM_CANDS; i++) {
        uarf_reload_tlb(cands[i]);
        uarf_mfence();
        uarf_lfence();
        UARF_LOG_INFO("\tCand %lu: %lu\n", i, uarf_get_access_time_a(_ptr(cands[i])));
    }

    // Time victim after cands, to ensure timing function is cached
    uarf_reload_tlb(victim);
    uarf_reload_tlb(victim);
    // usleep(500000);
    uarf_mfence();
    uarf_lfence();
    UARF_LOG_INFO("\tVictim: %lu\n", uarf_get_access_time_a(_ptr(victim)));

    UARF_TEST_PASS();
}

UARF_TEST_SUITE() {

    srand(uarf_get_seed());

    uarf_log_system_base_level = UARF_LOG_LEVEL_DEBUG;
    // uarf_log_system_tag = UARF_LOG_TAG_MEM;
    // uarf_log_system_level = UARF_LOG_LEVEL_TRACE;

    UARF_TEST_RUN_CASE(basic);

    UARF_TEST_PASS();
}
