#include "vsnip.h"
#include "errnum.h"
#include "lib.h"
#include "log.h"

#include <string.h>

int uarf_vsnip_align_alloc(UarfVsnipAlign *snip, uint64_t *base_addr_ptr,
                           uint64_t rem_size) {
    UARF_LOG_TRACE("(%p, %p, %lu)\n", snip, base_addr_ptr, rem_size);

    uarf_assert(snip);
    uarf_assert(base_addr_ptr);
    uarf_assert(snip->alignment > 0);

    uint64_t aligned_addr = ALIGN_UP(*base_addr_ptr, snip->alignment);
    uint64_t num_bytes = aligned_addr - *base_addr_ptr;

    // Check if enough space left
    if (num_bytes > rem_size) {
        UARF_LOG_DEBUG("Only %lu of required %lu bytes left\n", rem_size, num_bytes);
        return -ENOSPC;
    }

    memset(_ptr(*base_addr_ptr), NOP_BYTE, num_bytes);

    UARF_LOG_DEBUG("Padded stub from 0x%lx to 0x%lx\n", *base_addr_ptr,
                   *base_addr_ptr + num_bytes);

    *base_addr_ptr += num_bytes;

    uarf_assert(*base_addr_ptr == ALIGN_UP(*base_addr_ptr, snip->alignment));

    return ESUCCESS;
}

void uarf_vsnip_assert_align_alloc(UarfVsnipAssertAlign *snip, UarfStub *stub) {
    UARF_LOG_TRACE("(%p, %p)\n", snip, stub);

    uarf_assert(snip);
    uarf_assert(stub);

    UARF_LOG_DEBUG("Check that 0x%lx is aligned to %u\n", stub->end_addr,
                   snip->alignment);

    uarf_assert(snip->alignment > 0);

    if (snip->alignment == 1) {
        return;
    }
    uarf_assert(stub->end_addr % snip->alignment == 0);
}

void uarf_vsnip_dump_stub_alloc(UarfVsnipDumpStub *snip, UarfStub *stub) {
    UARF_LOG_TRACE("(%p, %p)\n", snip, stub);

    uarf_assert(snip);
    uarf_assert(stub);

    *snip->dump_to = *stub;
}

static int jmp_near_alloc(uint64_t *base_addr_ptr, uint64_t rem_size, uint32_t offset) {
    UARF_LOG_TRACE("(%p, %p, %lu)\n", base_addr_ptr, base_addr_ptr, rem_size);

    uarf_assert(base_addr_ptr);

    if (rem_size < 5) {
        return -ENOSPC;
    }

    uint8_t *bytes = (uint8_t *) (*base_addr_ptr);

    *base_addr_ptr += 5;

    UARF_LOG_DEBUG("Direct jump with offset 0x%x\n", offset);

    bytes[0] = 0xe9;
    bytes[1] = offset & 0xFF;
    bytes[2] = (offset >> 8) & 0xFF;
    bytes[3] = (offset >> 16) & 0xFF;
    bytes[4] = (offset >> 24) & 0xFF;

    return ESUCCESS;
}

int uarf_vsnip_jmp_near_abs_alloc(UarfVsnipJmpNearAbs *snip, uint64_t *base_addr_ptr,
                                  uint64_t rem_size) {
    UARF_LOG_TRACE("(%p, %p, %lu)\n", snip, base_addr_ptr, rem_size);

    uarf_assert(snip);
    uarf_assert(base_addr_ptr);

    int32_t offset = snip->target_addr - *base_addr_ptr - 5;
    return jmp_near_alloc(base_addr_ptr, rem_size, offset);
}

int uarf_vsnip_jmp_near_rel_alloc(UarfVsnipJmpNearRel *snip, uint64_t *base_addr_ptr,
                                  uint64_t rem_size) {

    UARF_LOG_TRACE("(%p, %p, %lu)\n", snip, base_addr_ptr, rem_size);

    uarf_assert(snip);
    uarf_assert(base_addr_ptr);

    return jmp_near_alloc(base_addr_ptr, rem_size, snip->offset);
}

int uarf_vsnip_fill_alloc(Uarf_VsnipFill *snip, uint64_t *base_addr_ptr,
                          uint64_t rem_size) {
    UARF_LOG_TRACE("(%p, %p, %lu)\n", snip, base_addr_ptr, rem_size);

    uarf_assert(snip);
    uarf_assert(base_addr_ptr);

    uint64_t required_size = snip->size * snip->times;

    UARF_LOG_DEBUG("Require %lu bytes to insert %d bytes %d times\n", required_size,
                   snip->size, snip->times);

    if (required_size > rem_size) {
        return -ENOSPC;
    }

    for (size_t i = 0; i < snip->times; i++) {
        memcpy(_ptr(*base_addr_ptr), snip->bytes, snip->size);
        *base_addr_ptr += snip->size;
    }
    return ESUCCESS;
}
