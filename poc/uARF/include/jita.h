/*
 * Just-In-Time Assembler allows to dynamically create object code.
 */

#pragma once

#include "log.h"
#include "psnip.h"
#include "stub.h"
#include "vsnip.h"
#include <stdbool.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG LOG_TAG_JITA
#endif

/**
 * A snippet is either physical or virtual
 */
typedef struct UarfSnip UarfSnip;
struct UarfSnip {
    enum Snip { PSNIP, VSNIP } type;
    union {
        UarfPsnip *psnip;
        UarfVsnip vsnip;
    };
};

#define JITA_CTXT_MAX_SNIPS 32
/**
 * Collection of snippets, used to build a stub.
 */
typedef struct UarfJitaCtxt UarfJitaCtxt;
struct UarfJitaCtxt {
    UarfSnip snips[JITA_CTXT_MAX_SNIPS];
    size_t n_snips;
};

/**
 * Get an initialized jita_ctxt_t.
 *
 * Only required in local function, as globals are initialized to zero.
 */
static __always_inline UarfJitaCtxt uarf_jita_init(void) {
    return (UarfJitaCtxt) {.n_snips = 0};
}

/**
 * Allocating a context to a stub at a given address.
 *
 * @param ctxt context to allocate
 * @param stub pointer to stub with allocation
 * @param addr address of arbitrary alignment to allocate the context on
 *
 * @NOTE: The stub must not have been alocated previously
 */
void uarf_jita_allocate(UarfJitaCtxt *ctxt, UarfStub *stub, uint64_t addr);

/**
 * Deallocate the stub of a context.
 *
 * @param ctxt not used
 * @param stub stub with allocation
 */
void uarf_jita_deallocate(UarfJitaCtxt *ctxt, UarfStub *stub);

/**
 * Add a virtual snippet to a context.
 */
void uarf_jita_push_vsnip(UarfJitaCtxt *ctxt, UarfVsnip snip);

/**
 * Add a physical snippet to a context.
 */
void uarf_jita_push_psnip(UarfJitaCtxt *ctxt, UarfPsnip *snip);

/**
 * Get the last added snip
 */
void uarf_jita_pop(UarfJitaCtxt *ctxt, UarfSnip *snip);

/**
 * Clone a jita
 */
void uarf_jita_clone(UarfJitaCtxt *from, UarfJitaCtxt *to);

/**
 * Create a virtual snippet that ensures that the next added snippet is aligned.
 */
void uarf_jita_push_vsnip_align(UarfJitaCtxt *ctxt, uint32_t align);

/**
 * Create a virtual snippet that asserts that the end of the stub is aligned.
 */
void uarf_jita_push_vsnip_assert_align(UarfJitaCtxt *ctxt, uint32_t alignment);

/**
 * Create a virtual snippet that dumps the stub at allocation time.
 */
void uarf_jita_push_vsnip_dump_stub(UarfJitaCtxt *ctxt, UarfStub *dump_to);

/**
 * Create a virtual snippet that does a direct jump to `target_addr`.
 */
void uarf_jita_push_vsnip_jmp_near_abs(UarfJitaCtxt *ctxt, uint64_t target_addr);

/**
 * Create a virtual snippet that does a direct jump with `offset`. `inclusive` controls
 * whether the jmp instruction size is part of `offset` or not.
 */
void uarf_jita_push_vsnip_jmp_near_rel(UarfJitaCtxt *ctxt, uint32_t offset,
                                       bool inclusive);

/**
 * Create a virtual snippet that adds `num` nops
 */
void uarf_jita_push_vsnip_fill_nop(UarfJitaCtxt *ctxt, uint32_t num);
