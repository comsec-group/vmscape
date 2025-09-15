#pragma once
#include "log.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_MEM
#endif

#define MMAP_FLAGS     (MAP_ANONYMOUS | MAP_PRIVATE)
#define MMAP_FLAGS_FIX (MMAP_FLAGS | MAP_FIXED_NOREPLACE)
#define PROT_RW        (PROT_READ | PROT_WRITE)
#define PROT_RWX       (PROT_RW | PROT_EXEC)

static inline void uarf_map_or_die(void *addr_p, size_t size) {
    if (mmap(addr_p, size, PROT_RWX, MMAP_FLAGS_FIX, -1, 0) == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map %luB at 0x%lx\n", size, _ul(addr_p));
        exit(1);
    };
}

static inline void uarf_map_huge_or_die(void *addr_p, size_t size) {
    // TODO: assert that a huge page is actually mapped
    if (mmap(addr_p, size, PROT_RWX, MMAP_FLAGS_FIX | MAP_HUGETLB, -1, 0) == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map %luB at 0x%lx\n", size, _ul(addr_p));
        exit(1);
    };
}

static inline uint64_t uarf_alloc_map_or_die(size_t size) {
    void *addr = mmap(NULL, size, PROT_RWX, MMAP_FLAGS, -1, 0);
    if (addr == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map %luB\n", size);
        exit(1);
    };
    return _ul(addr);
}

static inline uint64_t uarf_alloc_map_huge_or_die(size_t size) {
    // TODO: assert that a huge page is actually mapped
    void *addr = mmap(NULL, size, PROT_RWX, MMAP_FLAGS | MAP_HUGETLB, -1, 0);
    if (addr == MAP_FAILED) {
        UARF_LOG_ERROR("Failed to map %luB\n", size);
        exit(1);
    };
    return _ul(addr);
}

static inline void uarf_unmap_or_die(void *addr_p, size_t size) {
    if (munmap(addr_p, size)) {
        UARF_LOG_ERROR("Failed to unmap %lu bytees at 0x%lx\n", size, _ul(addr_p));
        exit(1);
    }
}

static inline void *uarf_malloc_or_die(size_t size) {
    void *addr = malloc(size);
    if (addr == NULL) {
        UARF_LOG_ERROR("Failed to malloc %lu bytes\n", size);
        exit(1);
    }
    return addr;
}

static inline void uarf_free_or_die(void *ptr) {
    free(ptr);
}

uint64_t uarf_va_to_pa(uint64_t va, uint64_t pid);
void *uarf_alloc_random_page(void);
void *uarf_alloc_random_hugepage(void);

/**
 * Access the page containing `addr` at some offset from `addr` to get the mapping into
 * the TLB.
 */
void uarf_reload_tlb(uint64_t addr);
