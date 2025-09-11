#include "mem.h"
#include "lib.h"
#include "page.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/*
 * Translate `va` of process `pid` to physcial address.
 *
 * If `pid` is 0, use own process.
 */
uint64_t uarf_va_to_pa(uint64_t va, uint64_t pid) {
    UARF_LOG_TRACE("(0x%lx, %lu)\n", va, pid);
    static int fd;
    if (pid) {
        char path[36];
        snprintf(path, sizeof(path), "/proc/%lu/pagemap", pid);
        fd = open(path, O_RDONLY);
    }
    else {
        fd = open("/proc/self/pagemap", O_RDONLY);
    }
    if (!fd) {
        UARF_LOG_ERROR("Failed to convert va to pa. Could not open pagemap\n");
        exit(1);
    }
    uint64_t pa_with_flags;
    if (pread(fd, &pa_with_flags, 8, (va & ~0xffful) >> 9) < 0) {
        UARF_LOG_ERROR("Failed to convert va to pa. Could not read pagemap\n");
        exit(1);
    }
    uint64_t pa = pa_with_flags & 0x7FFFFFFFFFFFFF;
    if (!pa) {
        UARF_LOG_ERROR(
            "PA is all zero. Probably you do not have sufficient permissions.\n");
        exit(1);
    }
    if (close(fd) == -1) {
        UARF_LOG_ERROR("Failed to close fd: %s\n", strerror(errno));
        exit(1);
    }
    return pa_with_flags << 12 | (va & 0xfff);
}

/**
 * Allocate and return pointer to an page at an arbitrary address.
 *
 * Simply using malloc does not allocate them at random addresses.
 */
void *uarf_alloc_random_page(void) {
    UARF_LOG_TRACE("()\n");
    const int flags = MMAP_FLAGS | MAP_FIXED;
    void *map;
    do {
        uint64_t cand_addr = uarf_rand47() & ~(PAGE_SIZE - 1);
        map = mmap(_ptr(cand_addr), PAGE_SIZE, PROT_RWX, flags, -1, 0);
    } while (map == MAP_FAILED);
    return map;
}

/**
 * Allocate and return pointer to a hugepage at an arbitrary address.
 *
 * Simply using malloc does not allocate them at random addresses.
 */
void *uarf_alloc_random_hugepage(void) {
    UARF_LOG_TRACE("()\n");
    const int flags = MMAP_FLAGS | MAP_FIXED | MAP_HUGETLB;
    void *map;
    do {
        uint64_t cand_addr = uarf_rand47() & ~(PAGE_SIZE_2M - 1);
        map = mmap(_ptr(cand_addr), PAGE_SIZE_2M, PROT_RWX, flags, -1, 0);
    } while (map == MAP_FAILED);
    return map;
}

void uarf_reload_tlb(uint64_t addr) {
    UARF_LOG_TRACE("(0x%lx)\n", addr);
    uint64_t page_base = addr & ~(PAGE_SIZE - 1);
    uint64_t page_offset = addr & (PAGE_SIZE - 1);
    page_offset += 64;
    page_offset %= PAGE_SIZE;
    *(volatile uint64_t *) (page_base + page_offset);
}
