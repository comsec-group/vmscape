/*
 * Allows the creation of virtual snippets. The object code is generate at runtime.
 */

#pragma once
#include "log.h"
#include "stub.h"
#include <stdint.h>

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_VSNIP
#endif

#define NOP_BYTE 0x90

/**
 * vsnippet to nop pad to reach an certain alignment
 */
typedef struct UarfVsnipAlign UarfVsnipAlign;
struct UarfVsnipAlign {
    uint32_t alignment;
};

/**
 * vsnippet to assert the alignment of the end of the stub
 */
typedef struct UarfVsnipAssertAlign UarfVsnipAssertAlign;
struct UarfVsnipAssertAlign {
    uint32_t alignment;
};

/**
 * vsnippet that dumps the stub at the time of allocation
 */
typedef struct UarfVsnipDumpStub UarfVsnipDumpStub;
struct UarfVsnipDumpStub {
    UarfStub *dump_to;
};

/**
 * vsnippet that inserts a direct absolute jump to `target_addr`
 */
typedef struct UarfVsnipJmpNearAbs UarfVsnipJmpNearAbs;
struct UarfVsnipJmpNearAbs {
    uint64_t target_addr;
};

/**
 * vsnippet that inserts a direct relative jump by `offset`
 */
typedef struct UarfVsnipJmpNearRel UarfVsnipJmpNearRel;
struct UarfVsnipJmpNearRel {
    uint64_t offset;
};

/**
 * vsnippet that inserts `bytes[:size]` `times`
 */
#define VSNIP_FILL_MAX_SIZE 1
typedef struct Uarf_VsnipFill Uarf_VsnipFill;
struct Uarf_VsnipFill {
    uint8_t bytes[VSNIP_FILL_MAX_SIZE];
    uint8_t size;
    uint32_t times;
};

/**
 * Represents a virtual snippet
 */
typedef struct UarfVsnip UarfVsnip;
struct UarfVsnip {
    enum Vsnip {
        VSNIP_ALIGN,
        VSNIP_ASSERT_ALIGN,
        VSNIP_DUMP_STUB,
        VSNIP_JMP_NEAR_ABS,
        VSNIP_JMP_NEAR_REL,
        VSNIP_FILL,
    } type;
    union {
        UarfVsnipAlign vsnip_align;
        UarfVsnipAssertAlign vsnip_assert_align;
        UarfVsnipDumpStub vsnip_dump_stub;
        UarfVsnipJmpNearAbs vsnip_jmp_near_abs;
        UarfVsnipJmpNearRel vsnip_jmp_near_rel;
        Uarf_VsnipFill vsnip_fill;
    };
};

/**
 * Allocation function for vsnip_align_t
 *
 * Insert as many nops to `*base_addr_ptr` to make the updated `*base_addr_ptr` aligned
 * to the requirement of the vsnip_align_t.
 *
 * @param snip pointer to vsnip to allocate
 * @param base_addr_ptr to address where to allocate to. Gets updated to new base
 * address
 * @param rem_size number of bytes that are mapped starting at `*base_addr_ptr`
 *
 * @returns -ENOSPC if `rem_size` is too small to allocate nsnip, else ESUCCESS
 */
int uarf_vsnip_align_alloc(UarfVsnipAlign *snip, uint64_t *base_addr_ptr,
                           uint64_t rem_size);

/**
 * Allocation function for vsnip_assert_align_t
 *
 * Assert that the end of the stub is aligned according to vsnip_assert_align_t
 * Does not actually allocate anything in the stub.
 */
void uarf_vsnip_assert_align_alloc(UarfVsnipAssertAlign *snip, UarfStub *stub);

/**
 * Allocation function for vsnip_dump_stub_t
 *
 * Writes the current stub_t to the pointer given in the vsnip_dump_stub_t
 * Does not actually allocate anything in the stub.
 */
void uarf_vsnip_dump_stub_alloc(UarfVsnipDumpStub *snip, UarfStub *stub);

/**
 * Allocation function for vsnip_jump_near_abs_t
 *
 * @param snip pointer to vsnip to allocate
 * @param base_addr_ptr to address where to allocate to. Gets updated to new base
 * address
 * @param rem_size number of bytes that are mapped starting at `*base_addr_ptr`
 *
 * @returns -ENOSPC if `rem_size` is too small to allocate nsnip, else ESUCCESS
 */
int uarf_vsnip_jmp_near_abs_alloc(UarfVsnipJmpNearAbs *snip, uint64_t *base_addr_ptr,
                                  uint64_t rem_size);

/**
 * Allocation function for vsnip_jump_near_rel_t
 *
 * @param snip pointer to vsnip to allocate
 * @param base_addr_ptr to address where to allocate to. Gets updated to new base
 * address
 * @param rem_size number of bytes that are mapped starting at `*base_addr_ptr`
 *
 * @returns -ENOSPC if `rem_size` is too small to allocate nsnip, else ESUCCESS
 */
int uarf_vsnip_jmp_near_rel_alloc(UarfVsnipJmpNearRel *snip, uint64_t *base_addr_ptr,
                                  uint64_t rem_size);

/**
 * Allocation function for vsnip_fill_t
 *
 * @param snip pointer to vsnip to allocate
 * @param base_addr_ptr to address where to allocate to. Gets updated to new base
 * address
 * @param rem_size number of bytes that are mapped starting at `*base_addr_ptr`
 *
 * @returns -ENOSPC if `rem_size` is too small to allocate nsnip, else ESUCCESS
 */
int uarf_vsnip_fill_alloc(Uarf_VsnipFill *snip, uint64_t *base_addr_ptr,
                          uint64_t rem_size);
