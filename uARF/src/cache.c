#include "cache.h"

#if defined UARCH && UARCH == zen4
UarfCache cache = {
    .cache_line_bits = 6,
    .cache_line_size = (1 << 6),
    .l1_set_bits = 6,
    .l1_ways = 8,
    .l2_set_bits = 11,
    .l2_ways = 8,
    .l3_set_bits = 15,
    .l3_ways = 16,
};
// #elif defined UARCH && UARCH == skylake
#else
UarfCache cache = {};
#warning "No cache design for this microarch"
#endif

uint64_t uarf_get_set_bits(uint64_t addr, uint64_t set_bits) {
    uint64_t mask = ((1 << set_bits) - 1) << cache.cache_line_bits;
    return addr & mask;
}

uint64_t uarf_get_l1_set(uint64_t addr) {
    return uarf_get_set_bits(addr, cache.l1_set_bits) >> cache.cache_line_bits;
}

uint64_t uarf_get_l2_set(uint64_t addr) {
    return uarf_get_set_bits(addr, cache.l2_set_bits) >> cache.cache_line_bits;
}

uint64_t uarf_get_l3_set(uint64_t addr) {
    return uarf_get_set_bits(addr, cache.l3_set_bits) >> cache.cache_line_bits;
}
