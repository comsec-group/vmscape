#include "evict.h"
#include "cache.h"
#include "lib.h"
#include "log.h"
#include "mem.h"
#include "page.h"

/**
 * Create eviction set with random elements of size `es_size`.
 */
void uarf_es_init(Es **es, size_t es_size) {

    *es = uarf_malloc_or_die(sizeof(Es));
    EsElem *head = uarf_malloc_or_die(sizeof(EsElem));
    EsElem *tail = uarf_malloc_or_die(sizeof(EsElem));
    uarf_dll_init(*es, head, NULL, tail, NULL);

    size_t i = 0;
    while (i < es_size) {
        uint64_t map = _ul(uarf_alloc_random_page());
        uarf_assert(!mlock(_ptr(map), PAGE_SIZE));

        for (size_t cl = 0; i < es_size && cl < PAGE_SIZE;
             i++, cl += cache.cache_line_size) {
            EsElem *elem = _ptr(map + cl);
            uarf_dll_node_init(*es, elem, _ptr(elem));
            uarf_dll_push_tail(*es, elem);
        }
    };
}

/**
 * Free all allocations made for the ES
 */
void uarf_es_deinit(Es *es) {
    // TODO: actually free all pages of the ES...
    uarf_free_or_die(es->head);
    uarf_free_or_die(es->tail);
    uarf_free_or_die(es);
}

/**
 * Access the eviction set `es` forward, backward, forward and repeat `num_rep`
 * times.
 */
void uarf_es_access_fbf(Es *es, size_t num_rep) {
    for (size_t round = 0; round < num_rep; round++) {
        // Forward access
        for (EsElem *elem = es->head; elem != NULL; elem = elem->next) {
            *(volatile uint64_t *) elem;
        }
        // Backward access
        for (EsElem *elem = es->tail; elem != NULL; elem = elem->prev) {
            *(volatile uint64_t *) elem;
        }
        // Forward access
        for (EsElem *elem = es->head; elem != NULL; elem = elem->next) {
            *(volatile uint64_t *) elem;
        }
    }
}

/**
 * Access the eviction set `es` with high locality,
 */
void uarf_es_access_local(Es *es, size_t num_rep) {
    for (size_t round = 0; round < num_rep; round++) {
        // Forward access
        for (EsElem *elem = es->head; elem != NULL; elem = elem->next) {
            EsElem *elem_access = elem;
            for (size_t i = 0; i < 32 && elem_access->type == UARF_DLL_NODE_TYPE_NORMAL;
                 i++) {
                *(volatile uint64_t *) elem_access;
            }
        }
        // // Backward access
        // for (EsElem *elem = es->tail; elem != NULL; elem = elem->prev) {
        //     EsElem *elem_access = elem;
        //     for (size_t i = 0; i < 10 && elem_access->type ==
        //     UARF_DLL_NODE_TYPE_NORMAL;
        //          i++) {
        //         *(volatile uint64_t *) elem_access;
        //     }
        // }
        // // Forward access
        // for (EsElem *elem = es->head; elem != NULL; elem = elem->next) {
        //     EsElem *elem_access = elem;
        //     for (size_t i = 0; i < 1 && elem_access->type ==
        //     UARF_DLL_NODE_TYPE_NORMAL;
        //          i++) {
        //         *(volatile uint64_t *) elem_access;
        //     }
        // }
    }
}

/**
 * How effective is es in evicting `victim` from cache, as indicated by
 * `is_in_cache`?
 *
 * 1: pefect, 0: not at all
 */
float uarf_es_effectiveness(Es *es, void *victim, size_t reps, bool is_in_cache(void *),
                            void es_access(Es *es, size_t num_rep)) {

    uint64_t num_evicted = 0;

    for (size_t i = 0; i < reps; i++) {
        *(volatile uint64_t *) &victim;
        es_access(es, 1);
        num_evicted += is_in_cache(_ptr(victim)) ? 0 : 1;
    }
    // UARF_LOG_DEBUG("ES evicted L1 %lu/%lu times\n", num_evicted, reps);

    return (float) num_evicted / reps;
}

/**
 * Reduce the number of elements in `es` such that it still evicts `victim` by
 * means of `es_eff`.
 */
size_t uarf_es_reduce(Es *es, void *victim,
                      float es_eff(Es *es, void *victim, size_t reps,
                                   void es_access(Es *es, size_t num_rep)),
                      void es_access(Es *es, size_t num_rep)) {
    UARF_LOG_TRACE("(%p, %p, %p, %p)\n", es, victim, es_eff, es_access);

    size_t es_effective_size = uarf_dll_size(es);

    const size_t REPS = 500;

    while (1) {
        bool kill_in_round = false;

        uarf_dll_for_each(es, kill_cand) {
            if (kill_cand->type != UARF_DLL_NODE_TYPE_NORMAL) {
                continue;
            }

            float eff_cur = 0;
            size_t i = 0;
            do {
                eff_cur = es_eff(es, victim, REPS, es_access);
                UARF_LOG_DEBUG("Current eff: %f\n", eff_cur);
                if (i++ > 10) {
                    printf("stuuuuck\n");
                }
            } while (eff_cur <= 0.5);

            // UARF_LOG_DEBUG("Cur eff with %lu elements: %f\n", es_effective_size,
            // eff_cur);
            //
            // // Sanity check
            // if (eff_cur <= 0.5) {
            //     // Check if fluke
            //     eff_cur = es_eff(es, victim, 20 * REPS);
            //     if (eff_cur > 0.5) {
            //         UARF_LOG_INFO("Continue and pretend nothing happened\n");
            //     }
            //     else {
            //         UARF_LOG_WARNING("Non-effective ES detection. Should not
            //         happen\n"); uarf_assert(0); return -1;
            //     }
            // }

            // Remove candidate and check new eff
            UarfDllNode *parent = kill_cand->prev;
            uarf_dll_remove(kill_cand);

            float eff_new = es_eff(es, victim, REPS, es_access);
            UARF_LOG_DEBUG("Remove candidate %d leads to eff %f\n", kill_cand->id,
                           eff_new);

            if (eff_cur * 0.95 < eff_new) {
                UARF_LOG_INFO("-- %d is not relevant (%f), remove\n", kill_cand->id,
                              eff_new);
                es_effective_size--;
                uarf_assert(es_effective_size > 0);
                kill_in_round = true;
                // uarf_assert(uarf_dll_size(es) == es_effective_size);
            }
            else {
                uarf_dll_push_after(kill_cand, parent);
                // uarf_assert(uarf_dll_size(es) == es_effective_size);
            }
        }
        if (!kill_in_round) {
            break;
        }
    }
    uarf_assert(uarf_dll_size(es) == es_effective_size);
    return es_effective_size;
}
