/**
 * Measure Cache Latency
 *
 * Determine the times required to access different cache levels.
 * This measurement is dependent on the measurement method.
 *
 * Zen4:
 * - L1: 6
 * - L2: 16
 * - L3: 51
 * - Mem: 430
 *
 * Zen4 (Should be, according so SOG):
 * - L1: 4
 * - L2: 14
 * - L3: 50
 * - Mem: ?
 *
 * The latencies seem reasonable, however, the correlation between memory size and cache
 * level not really. This is very likely due to prefetching. But we are also not really
 * convened by that.
 */

#include "lib.h"
#include "log.h"
#include "mem.h"
#include "page.h"
#include "test.h"
#include <string.h>

typedef struct MemConfig MemConfig;
struct MemConfig {
    /// Total memory in B that is getting accessed
    uint64_t mem_size;
    uint64_t page_size;
    uint64_t num_iter;
    uint64_t (*measure_func)(const void *);
};

int compare_uint64(const void *a, const void *b) {
    uint64_t arg1 = *(const uint64_t *) a;
    uint64_t arg2 = *(const uint64_t *) b;

    if (arg1 < arg2)
        return -1;
    if (arg1 > arg2)
        return 1;
    return 0;
}

UARF_TEST_CASE_ARG(basic, config) {

    const uint64_t CACHE_LINE_SIZE = 64;

    MemConfig *cfg = config;
    uarf_assert(IS_POW_TWO(cfg->mem_size));
    uarf_assert(cfg->page_size == PAGE_SIZE || cfg->page_size == PAGE_SIZE_2M ||
                cfg->page_size == PAGE_SIZE_1G);
    uarf_assert(cfg->num_iter);

    // Allocate pages
    uint64_t num_pages = div_round_up(cfg->mem_size, cfg->page_size);

    uint64_t *pages_p = uarf_malloc_or_die(num_pages * sizeof(uint64_t));

    UARF_LOG_DEBUG("Allocate %lu pages of size %luB\n", num_pages, cfg->page_size);
    for (size_t i = 0; i < num_pages; i++) {
        if (cfg->page_size == PAGE_SIZE) {
            pages_p[i] = uarf_alloc_map_or_die(cfg->page_size);
            uarf_assert(pages_p[i]);
        }
        else if (cfg->page_size == PAGE_SIZE_2M) {
            pages_p[i] = uarf_alloc_map_huge_or_die(cfg->page_size);
            uarf_assert(pages_p[i]);
        }
        else if (cfg->page_size == PAGE_SIZE_1G) {
            pages_p[i] = uarf_alloc_map_huge_or_die(cfg->page_size);
            uarf_assert(pages_p[i]);
        }
        else {
            uarf_assert(0);
        }
        // Ensure not demand allocated and zero-page backed
        memset(_ptr(pages_p[i]), i, cfg->page_size);
    }

    // Access data
    UARF_LOG_DEBUG("Start measurement\n");

    uint64_t num_accesses = cfg->mem_size / CACHE_LINE_SIZE;
    uarf_assert(IS_POW_TWO(num_accesses));

    uint64_t access_per_page = cfg->page_size / CACHE_LINE_SIZE;

    UARF_LOG_DEBUG("Alloc %lu results\n", cfg->num_iter * num_accesses);

    uint64_t *res = malloc(cfg->num_iter * num_accesses * sizeof(uint64_t));
    uarf_assert(res);
    size_t res_i = 0;

    for (size_t iter = 0; iter < cfg->num_iter; iter++) {
        for (size_t access = 0; access < num_accesses; access++) {
            // size_t k = (access * 7817 + 4349) & (num_accesses - 1);
            // size_t k = (access * 7841 + 4943) & (num_accesses - 1);
            size_t k = (access *   9311 + 197) & (num_accesses - 1);
            // size_t k = (access *   13 + 7) & (num_accesses - 1);
            size_t page_i = k / access_per_page;
            size_t page_offset = k - (page_i * access_per_page);
            uarf_assert(page_i < num_pages);
            uarf_assert(page_offset < access_per_page);
            res[res_i++] = cfg->measure_func(_ptr(pages_p[page_i] + page_offset));
        }
    }
    uarf_assert(res_i == cfg->num_iter * num_accesses);

    // Extract result
    qsort(res, cfg->num_iter * num_accesses, sizeof(res[0]), compare_uint64);
    uint64_t median = res[cfg->num_iter * num_accesses / 2];

    // Unmap result and pages
    uarf_free_or_die(res);

    for (size_t i = 0; i < num_pages; i++) {
        uarf_unmap_or_die(_ptr(pages_p[i]), cfg->page_size);
    }

    return median;
}

uint64_t test_sizes[22] = {1,     2,      4,      8,      16,      32,     64,    128,
                           256,   512,    1024,   2048,   4096,    8192,   16384, 32768,
                           65536, 131072, 262144, 524288, 1048576, 2097152};

MemConfig cfg1 = {
    .page_size = PAGE_SIZE,
    // .page_size = PAGE_SIZE_2M,
    // .page_size = PAGE_SIZE_1G,
    .mem_size = 0,
    .num_iter = 10,
    .measure_func = uarf_get_access_time_a,
};

UARF_TEST_SUITE() {

    uarf_pi_init();

    // Disable prefetcher
    // Does not seem to work
    uarf_wrmsr_user(0xc0000108, 47);

    uarf_log_system_base_level = UARF_LOG_LEVEL_INFO;

    UARF_LOG_INFO("Acceess times:\n");

    for (size_t i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); i++) {
        cfg1.mem_size = (test_sizes[i] << 10);

        uint64_t dt = UARF_TEST_RUN_CASE_ARG(basic, &cfg1);
        printf("%lu, %lu\n", cfg1.mem_size >> 10, dt);
    }

    uarf_pi_deinit();

    return 0;
}
