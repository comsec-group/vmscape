/**
 * Are caches still indexed in the same way?
 *
 * Are the set bit still valid, or do they use some sort of hash?
 *
 * Allocate a huge eviction set for a victim, then reduced it by dropping elements that
 * are not critical. Observe the VAs of the final elements.
 *
 * ## L1
 * - 32KB
 * - 8 Way
 * - 2^6 = 64 sets
 * - uses UTAG
 * - uarf_get_access_time_m of 6
 *
 * ## L2
 * - 1 MB (or 512 KB)
 * - 8 Way
 * - 2^11 = 2048 sets
 * - uarf_get_access_time_m of 16
 * - L1 is inclusive in L2
 * - uses some very advanced replacement policy (not LRU)
 *
 * ## L3
 * - Up to 32 MB
 * - 16 Way
 * - Up to 2^15 = 32768 sets
 * - Slices
 * - Shared among 8 cores
 * - Not inclusive
 * - May use some advanced replacement policy
 * - uarf_get_access_time_m of ~51
 *
 * # Results
 * - L1:
 */

#include "dll.h"
#include "evict.h"
#include "lib.h"
#include "mem.h"
#include "page.h"
#include "test.h"
#include <string.h>

typedef UarfDll Es;
typedef UarfDllNode EsElem;

/**
 * Get the cache set bits of p.
 */
uint64_t get_set_bits(void *addr, uint8_t num_set_bits) {
    uint64_t mask = ((1ul << num_set_bits) - 1) << CACHE_LINE_BITS;
    return _ul(addr) & mask;
}

/**
 * Get the cache set that `addr` maps to, assuming `num_set_bits` are used.
 */
uint64_t get_set(void *addr, uint8_t num_set_bits) {
    return get_set_bits(addr, num_set_bits) >> 6;
}

/**
 * Get the L1 cache set that `addr` maps to.
 */
uint64_t get_l1_set(void *addr) {
    return get_set(addr, L1_SET_BITS);
}

/**
 * Get the L2 cache set that `addr` maps to.
 */
uint64_t get_l2_set(void *addr) {
    return get_set(addr, L2_SET_BITS);
}

/**
 * Get the L3 cache set that `addr` maps to.
 */
uint64_t get_l3_set(void *addr) {
    return get_set(addr, L3_SET_BITS);
}

/**
 * Indicate whether the victim is in L1 or not
 */
bool is_in_l1(void *victim) {
    return uarf_get_access_time_a(victim) <= L1_ACCESS_DT;
}

/**
 * Indicate whether the victim is in L2 or not
 */
bool is_in_l2(void *victim) {
    uint64_t a = uarf_get_access_time_a(victim);
    // printf("%lu\n", a);
    return a <= L2_ACCESS_DT;
}

/**
 * How effective is es in evicting `victim` from l1?
 *
 * 1: pefect, 0: not at all
 */
float es_l1_effectiveness(Es *es, void *victim, size_t reps,
                          void es_access(Es *es, size_t num_rep)) {
    return uarf_es_effectiveness(es, victim, reps, is_in_l1, es_access);
}

/**
 * How effective is es in evicting `victim` from l2?
 *
 * 1: pefect, 0: not at all
 */
float es_l2_effectiveness(Es *es, void *victim, size_t reps,
                          void es_access(Es *es, size_t num_rep)) {
    return uarf_es_effectiveness(es, victim, reps, is_in_l2, es_access);
}

void print_addr_info(uint64_t addr) {
    uint64_t va = addr;
    uint64_t pa = uarf_va_to_pa(va, 0);
    uint64_t va_l1 = get_l1_set(_ptr(va));
    uint64_t pa_l1 = get_l1_set(_ptr(pa));
    uint64_t va_l2 = get_l2_set(_ptr(va));
    uint64_t pa_l2 = get_l2_set(_ptr(pa));
    printf("va: 0x%lx, pa: 0x%lx, L1: %lu | %lu, L2: %lu | %lu\n", va, pa, va_l1, pa_l1,
           va_l2, pa_l2);
}

/**
 * Build eviction sets for the L1 cache
 */
UARF_TEST_CASE(l1_eviction) {
    uint64_t victim_page = uarf_alloc_map_or_die(PAGE_SIZE);
    void *victim = _ptr(victim_page + (random() % PAGE_SIZE));

    Es es;
    EsElem head;
    EsElem tail;

    uarf_dll_init(&es, &head, NULL, &tail, NULL);

    uint64_t victim_l1_set = get_l1_set(victim);
    UARF_LOG_INFO("Victim maps into L1 cache set %lu\n", victim_l1_set);

    const uint64_t ES_SIZE_INIT = 800;
    UARF_LOG_DEBUG("Building eviction set with %lu entries\n", ES_SIZE_INIT);

    // Build eviction set for victim L1
    // for (size_t i = 0; i < ES_SIZE_INIT; i++) {
    //     uint64_t map = _ul(alloc_random_page());
    //     EsElem *elem = _ptr(map + (victim_l1_set << CACHE_LINE_BITS));
    //     uarf_dll_node_init(&es, elem, _ptr(elem));
    //     uarf_dll_push_tail(&es, elem);
    //     uarf_assert(get_l1_set(elem) == victim_l1_set);
    // }

    // Build random eviction set
    uarf_es_init(&es, ES_SIZE_INIT);

    UARF_LOG_DEBUG("Trying to reduce ES\n");
    size_t es_size =
        uarf_es_reduce(&es, victim, es_l1_effectiveness, uarf_es_access_local);

    UARF_LOG_INFO("Reduced ES from %lu to %lu elements\n", ES_SIZE_INIT, es_size);

    UARF_LOG_INFO("ES:\n");
    size_t i = 0;
    uarf_dll_for_each(&es, elem) {
        if (elem->type != UARF_DLL_NODE_TYPE_NORMAL) {
            continue;
        }
        uarf_assert(_ptr(elem) == elem->data);
        printf("%lu: %d; ", i++, elem->id);
        print_addr_info(_ul(elem->data));
    }
    printf("Victim; ");
    print_addr_info(_ul(victim));

    // Last sanity check...
    uarf_assert(es_l1_effectiveness(&es, victim, 10, uarf_es_access_local) > 0.5);

    // TODO: free stuff
    UARF_TEST_PASS();
}

UARF_TEST_CASE(l2_eviction) {
    // TODO: address somehow not random enough
    uint64_t victim_page = uarf_alloc_map_or_die(PAGE_SIZE);
    void *victim = _ptr(victim_page + (random() % PAGE_SIZE));
    memset(_ptr(victim_page), 0x1, PAGE_SIZE);

    uarf_assert(!mlock(_ptr(victim_page), PAGE_SIZE));

    Es es;
    EsElem head;
    EsElem tail;

    uarf_dll_init(&es, &head, NULL, &tail, NULL);

    uint64_t victim_l2_set = get_l2_set(victim);
    UARF_LOG_INFO("Victim maps into L2 cache set %lu\n", victim_l2_set);

    const uint64_t ES_SIZE_INIT = 2000;
    UARF_LOG_DEBUG("Building eviction set with %lu entries\n", ES_SIZE_INIT);

    // Build eviction set for victim L2
    // for (size_t i = 0; i < ES_SIZE_INIT; i++) {
    //     uint64_t map = _ul(alloc_random_page());
    //     EsElem *elem = _ptr(map + (victim_l2_set << CACHE_LINE_BITS));
    //     uarf_dll_node_init(&es, elem, _ptr(elem));
    //     uarf_dll_push_tail(&es, elem);
    //     uarf_assert(get_l2_set(elem) == victim_l2_set);
    // }

    // Build random eviction set
    uarf_es_init(&es, ES_SIZE_INIT);

    UARF_LOG_DEBUG("Trying to reduce ES\n");
    size_t es_size =
        uarf_es_reduce(&es, victim, es_l2_effectiveness, uarf_es_access_local);
    UARF_LOG_INFO("Reduced ES from %lu to %lu elements\n", ES_SIZE_INIT, es_size);

    UARF_LOG_INFO("ES:\n");
    size_t i = 0;
    uarf_dll_for_each(&es, elem) {
        if (elem->type != UARF_DLL_NODE_TYPE_NORMAL) {
            continue;
        }
        uarf_assert(_ptr(elem) == elem->data);
        printf("%lu: %d; ", i++, elem->id);
        print_addr_info(_ul(elem->data));
    }
    printf("Victim; ");
    print_addr_info(_ul(victim));

    // TODO: free stuff
    UARF_TEST_PASS();
}

UARF_TEST_SUITE() {

    srand(uarf_get_seed());

    // Linked needs to fit into cache line
    uarf_assert(sizeof(EsElem) < CACHE_LINE_SIZE);

    uarf_log_system_base_level = UARF_LOG_LEVEL_DEBUG;

    UARF_TEST_RUN_CASE(l1_eviction);
    // UARF_TEST_RUN_CASE(l2_eviction);

    UARF_TEST_PASS();
}
