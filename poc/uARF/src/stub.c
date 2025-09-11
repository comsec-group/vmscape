#include "stub.h"
#include "lib.h"
#include "log.h"
#include "mem.h"

#include "page.h"
#include <string.h>

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_STUB
#endif

void uarf_stub_add(UarfStub *stub, uint64_t start, uint64_t size) {
    UARF_LOG_TRACE("(%p, 0x%lx, %lu)\n", stub, start, size);

    uarf_assert(stub);
    uarf_assert(stub->base_addr);
    uarf_assert(stub->addr);
    uarf_assert(stub->end_addr);
    uarf_assert(stub->base_ptr <= stub->ptr);
    uarf_assert(stub->ptr <= stub->end_ptr);

    if (size == 0) {
        return;
    }

    // Check if enough space left
    while (uarf_stub_size_free(stub) < size) {
        uarf_stub_extend(stub);
    }

    UARF_LOG_DEBUG("Stub has now size %luB\n", stub->size);

    UARF_LOG_DEBUG("Copy code of size %lu to 0x%lx\n", size, stub->end_addr);

    memcpy(stub->end_ptr, _ptr(start), size);
    stub->end_ptr += size;
    uarf_assert(stub->end_addr <= stub->base_addr + stub->size);
}

void uarf_stub_extend(UarfStub *stub) {
    UARF_LOG_TRACE("(%p)\n", stub);
    uarf_assert(stub);
    uarf_assert(stub->base_addr);
    uarf_assert(stub->addr);
    uarf_assert(stub->end_addr);
    uarf_assert(stub->base_ptr <= stub->ptr);
    uarf_assert(stub->ptr <= stub->end_ptr);

    uint64_t next_page = stub->base_addr + stub->size;
    UARF_LOG_DEBUG("Map one more page starting at 0x%lx\n", next_page);
    // vmap_kern_4k_or_die(_ptr(next_page), get_free_frame()->mfn, L1_PROT);
    uarf_map_or_die(_ptr(next_page), PAGE_SIZE);
    stub->size += PAGE_SIZE;
}

void uarf_stub_free(UarfStub *stub) {
    UARF_LOG_TRACE("(%p)\n", stub);
    uarf_assert(stub);
    uarf_assert(stub->base_addr);
    uarf_assert(stub->addr);
    uarf_assert(stub->end_addr);
    uarf_assert(stub->base_ptr <= stub->ptr);
    uarf_assert(stub->ptr <= stub->end_ptr);

    uint64_t current_page = stub->base_addr;
    size_t remaining_size = stub->size;

    UARF_LOG_DEBUG("There are %lu B to unmap\n", remaining_size);

    while (remaining_size) {
        UARF_LOG_DEBUG("Unmap page at 0x%lx\n", current_page);
        uarf_unmap_or_die(_ptr(current_page), PAGE_SIZE);
        remaining_size -= PAGE_SIZE;
        current_page += PAGE_SIZE;
    }

    stub->size = 0;
    stub->base_ptr = 0;
    stub->addr = 0;
    stub->end_addr = 0;
}

uint64_t uarf_stub_size_free(UarfStub *stub) {
    UARF_LOG_TRACE("(%p)\n", stub);

    uarf_assert(stub);
    uarf_assert(stub->base_addr);
    uarf_assert(stub->addr);
    uarf_assert(stub->end_addr);
    uarf_assert(stub->base_ptr <= stub->ptr);
    uarf_assert(stub->ptr <= stub->end_ptr);

    // Happens when the stub is first assigned to
    if (stub->size == 0) {
        return 0;
    }

    uint64_t stub_end = stub->base_addr + stub->size;
    uarf_assert(stub_end >= stub->end_addr);

    return stub->base_addr + stub->size - stub->end_addr;
}
