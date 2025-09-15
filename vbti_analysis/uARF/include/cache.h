#pragma once
/**
 * Different constants and functions for interacting with caches.
 */

#include <stdint.h>

typedef struct UarfCache UarfCache;
struct UarfCache {
    uint8_t cache_line_bits;
    uint8_t cache_line_size;
    uint8_t l1_set_bits;
    uint8_t l1_ways;
    // uint8_t L1_ACCESS_DT = 6;

    uint8_t l2_set_bits;
    uint8_t l2_ways;
    // uint8_t L2_ACCESS_DT = 16;

    uint8_t l3_set_bits;
    uint8_t l3_ways;
    // uint8_t L3_ACCESS_DT = 51;
};

extern UarfCache cache;

/**
 * Get the cache set bits of p.
 */
uint64_t uarf_get_set_bits(uint64_t addr, uint64_t set_bits);

/**
 * Get the L1 cache set that p maps to.
 */
uint64_t uarf_get_l1_set(uint64_t addr);

/**
 * Get the L2 cache set that p maps to.
 */
uint64_t uarf_get_l2_set(uint64_t addr);

/**
 * Get the L3 cache set that p maps to.
 */
uint64_t uarf_get_l3_set(uint64_t addr);
