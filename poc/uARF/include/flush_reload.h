/**
 * Flush+Reload tools.
 */

#pragma once

// L3 miss
#define FR_THRESH 200

// Address of first flush and reload buffer
#define FR_BUF 0xfff1f200000ul

// Address of second flush and reload buffer
#define FR_BUF2 0xfff2f200000ul

// Address of result array
#define FR_RES 0xfff3f200000ul

// Distance between two entries in the buffer
#define FR_STRIDE_BITS 12
#define FR_STRIDE      (1UL << FR_STRIDE_BITS)

// #define FR_OFFSET 0x180
#define FR_OFFSET 0x0

#ifndef __ASSEMBLY__
#include "compiler.h"
#include "lib.h"
#include "log.h"
#include <string.h>

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_FR
#endif

#define FR_CONFIG_BIN_MAPPING_SIZE 10
typedef struct UarfFrConfig UarfFrConfig;
struct UarfFrConfig {
    // First flush and reload buffer
    struct {
        // Page Aligned address
        union {
            char *base_p;
            uintptr_t base_addr;
        };
        // At some offset
        union {
            char *p;
            uintptr_t addr;
        };
        // Address that we use from host when guest interacts with buffer
        union {
            char *handle_p;
            uintptr_t handle_addr;
        };
    } buf;
    // Second flush and reload buffer
    struct {
        // Page Aligned address
        union {
            char *base_p;
            uintptr_t base_addr;
        };
        // At some offset
        union {
            char *p;
            uintptr_t addr;
        };
    } buf2;
    // Address of results array
    // [[bin 0 for all num_slots entries], [bin 1 for all num_slots entries], ... [bin
    // num_bins - 1 for all num_slots entries]]
    union {
        uint32_t *res_p;
        uintptr_t res_addr;
    };
    // Number of slots (entries) in the buffer
    uint16_t num_slots;
    // Number of bins to distribute the
    uint8_t num_bins;
    // Cache hit/miss threshold
    uint16_t thresh;
    // Mapping of iterations to bins
    // Having this as a variable sized array leads to weird bugs when accessing the array
    size_t bin_map[FR_CONFIG_BIN_MAPPING_SIZE];
    // Size of buffer and result array in bytes
    size_t buf_size;
    size_t res_size;
};

static __always_inline void uarf_fr_reset(UarfFrConfig *conf) {
    UARF_LOG_TRACE("(%p)\n", conf);
    memset(conf->res_p, 0, conf->num_slots * conf->num_bins * sizeof(uint32_t));
}

void uarf_fr_flush(UarfFrConfig *conf);
void uarf_fr_reload_binned(UarfFrConfig *conf, size_t iteration);

UarfFrConfig uarf_fr_init(uint16_t num_slots, uint8_t num_bins, size_t *bin_map);

void uarf_fr_deinit(UarfFrConfig *conf);
uint64_t uarf_fr_num_hits(UarfFrConfig *conf);
void uarf_fr_print(UarfFrConfig *conf);

static __always_inline void uarf_fr_reload(UarfFrConfig *conf) {
    UARF_LOG_TRACE("(%p)\n", conf);
    uarf_fr_reload_binned(conf, 0);
}

#endif /* __ASSEMBLY__ */
