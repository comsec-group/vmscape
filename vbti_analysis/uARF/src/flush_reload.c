#include "flush_reload.h"
#include "compiler.h"
#include "lib.h"
#include "log.h"
#include "mem.h"
#include <string.h>

void uarf_fr_flush(UarfFrConfig *conf) {
    UARF_LOG_TRACE("(%p)\n", conf);
    uarf_mfence();
    for (uint64_t i = 0; i < conf->num_slots; i++) {
        volatile void *p = conf->buf.handle_p + i * FR_STRIDE;
        uarf_clflush(p);
    }
    uarf_mfence(); // Required to enforce ordering of cl flush with subsequent
                   // memory operations on AMD
    uarf_sfence();
    uarf_lfence();
}

// Calculate in which bin `iteration` goes
static size_t uarf_get_bin(UarfFrConfig *conf, size_t iteration) {
    UARF_LOG_TRACE("(%p, %lu)\n", conf, iteration);

    for (size_t i = 0; i < conf->num_bins; i++) {
        if (iteration <= conf->bin_map[i]) {
            return i;
        }
    }

    // If no bin found, take last one
    return conf->num_bins - 1;
}

void uarf_fr_reload_binned(UarfFrConfig *conf, size_t iteration) {
    UARF_LOG_TRACE("(%p, %lu)\n", conf, iteration);

    size_t bin_i = uarf_get_bin(conf, iteration);
    uint32_t *res_bin_p = (uint32_t *) (conf->res_p + bin_i * conf->num_slots);
    UARF_LOG_DEBUG("result address: %p\n", res_bin_p);

    for (uint64_t k = 0; k < conf->num_slots; ++k) {
        void *p = conf->buf.handle_p + FR_STRIDE * k;
        uarf_reload_tlb(_ul(p));
    }
    uarf_mfence();

    // Should be completely unrolled to prevent data triggering the data cache
    // prefetcher
#pragma GCC unroll 1024
    for (uint64_t k = 0; k < conf->num_slots; ++k) {
        // NOTE: If there are many false positives in the result, play with this
        // function size_t buf_i = (k * 13 + 9) & (conf->num_slots - 1);
        size_t buf_i = (k * 421 + 9) & (conf->num_slots - 1);
        void *p = conf->buf.handle_p + FR_STRIDE * buf_i;
        uint64_t dt = uarf_get_access_time(p);
        if (dt < conf->thresh) {
            res_bin_p[buf_i]++;
        }
    }
    uarf_mfence();
}

// Initialize the flush and reload buffer, its dummy version  and history
// buffer. Needs to be done from kernel space
UarfFrConfig uarf_fr_init(uint16_t num_slots, uint8_t num_bins, size_t *bin_map) {
    UARF_LOG_TRACE("(%u, %u, %p)\n", num_slots, num_bins, bin_map);

    // Assert nm_slots is power of two. Fr_reload_range only works for 2^n
    uarf_assert(IS_POW_TWO(num_slots));

    uarf_assert(num_bins != 0);

    UarfFrConfig conf = (UarfFrConfig) {
        .buf = {.base_addr = FR_BUF,
                .addr = FR_BUF + FR_OFFSET,
                .handle_addr = FR_BUF + FR_OFFSET},
        .buf2 = {.base_addr = FR_BUF2, .addr = FR_BUF2 + FR_OFFSET},
        .res_addr = FR_RES,
        .num_slots = num_slots,
        .num_bins = num_bins,
        .thresh = FR_THRESH,
        .buf_size = ROUND_2MB_UP(num_slots * FR_STRIDE + 0x1000ul),
        .res_size = num_slots * num_bins * sizeof(uint32_t),
    };

    if (num_bins > 1) {
        memcpy(conf.bin_map, bin_map, FR_CONFIG_BIN_MAPPING_SIZE * sizeof(size_t));
    }

    uarf_map_huge_or_die(conf.buf.base_p, conf.buf_size);
    uarf_map_or_die(conf.buf2.base_p, conf.buf_size);
    uarf_map_or_die(conf.res_p, conf.res_size);

    // Madvise is for transparent huge pages only...
    madvise(conf.buf.p, conf.buf_size, MADV_HUGEPAGE);
    madvise(conf.buf2.p, conf.buf_size, MADV_HUGEPAGE);

    // Ensure it is not zero-page backed
    for (size_t i = 0; i < conf.num_slots; i++) {
        memset(conf.buf.p + i * FR_STRIDE, '0' + i, FR_STRIDE);
    }

    // Assign FR_BUF[i] = i + 1
    // Used to create dependant memory accesses
    for (size_t i = 0; i < conf.num_slots; i++) {
        *(uint64_t *) (conf.buf.p + (i * FR_STRIDE)) = i + 1;
    }

    return conf;
}

void uarf_fr_deinit(UarfFrConfig *conf) {
    UARF_LOG_TRACE("(%p)\n", conf);

    uarf_unmap_or_die(conf->buf.base_p, conf->buf_size);
    uarf_unmap_or_die(conf->buf2.base_p, conf->buf_size);
    uarf_unmap_or_die(conf->res_p, conf->res_size);
}

uint64_t uarf_fr_num_hits(UarfFrConfig *conf) {
    uarf_assert(conf->num_bins == 1); // Only works with 1 bin for now
    uint64_t sum = 0;
    for (size_t i = 0; i < conf->num_slots; i++) {
        sum += conf->res_p[i];
    }
    return sum;
}

void uarf_fr_print(UarfFrConfig *conf) {
    UARF_LOG_TRACE("(%p)\n", conf);

    if (conf->num_bins == 1) {
        for (size_t i = 0; i < conf->num_slots; i++) {
            printf("%s%04u " UARF_LOG_C_RESET, conf->res_p[i] ? UARF_LOG_C_DARK_RED : "",
                   conf->res_p[i]);
        }
        printf("\n");
        return;
    }

    // Calculate max possible number of elements per bin
    uint64_t max_bin[conf->num_bins];
    max_bin[0] = conf->bin_map[0] + 1;
    for (size_t i = 1; i < conf->num_bins; i++) {
        max_bin[i] = conf->bin_map[i] - conf->bin_map[i - 1];
    }

    uint64_t total[conf->num_slots];
    memset(total, 0, sizeof(total));

    for (uint8_t bin = 0; bin < conf->num_bins; bin++) {
        if (bin < conf->num_bins - 1) {
            printf("%5lu (%4lu): ", conf->bin_map[bin], max_bin[bin]);
        }
        else {
            printf("   remainder: ");
        }
        for (size_t slot = 0; slot < conf->num_slots; slot++) {
            uint32_t hits = *(conf->res_p + bin * conf->num_slots + slot);
            total[slot] += hits;
            printf("%s%04u " UARF_LOG_C_RESET, hits ? UARF_LOG_C_DARK_RED : "", hits);
        }
        printf("\n");
    }

    printf("-------------");
    for (size_t i = 0; i < conf->num_slots; i++) {
        printf("-----");
    }
    printf("\n");

    // Print total sum
    printf("       Total: ");
    for (size_t i = 0; i < conf->num_slots; i++) {
        printf("%s%04ld " UARF_LOG_C_RESET, total[i] ? UARF_LOG_C_DARK_RED : "",
               total[i]);
    }
    printf("\n");

    printf("=============");
    for (size_t i = 0; i < conf->num_slots; i++) {
        printf("=====");
    }
    printf("\n");
}
