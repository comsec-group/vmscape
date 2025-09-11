#include "jita.h"
#include "errnum.h"
#include "lib.h"

/**
 * Allocate a snip
 */
static void _uarf_allocate_psnip(UarfJitaCtxt *ctxt, UarfStub *stub, UarfPsnip *snip) {
    UARF_LOG_TRACE("(%p, %p, %p)\n", ctxt, stub, snip);
    uarf_assert(stub);

    uarf_assert(snip);
    uarf_assert(snip->addr);
    uarf_assert(snip->end_addr);

    uarf_stub_add(stub, snip->addr, uarf_psnip_size(snip));
}

/**
 * Allocate a snip
 */
void _uarf_allocate_vsnip(UarfJitaCtxt *ctxt, UarfStub *stub, UarfVsnip *snip) {
    UARF_LOG_TRACE("(%p, %p, %p)\n", ctxt, stub, snip);

    uarf_assert(stub);
    uarf_assert(stub->base_addr);
    uarf_assert(stub->addr);
    uarf_assert(stub->end_addr);
    uarf_assert(stub->base_ptr <= stub->ptr);
    uarf_assert(stub->ptr <= stub->end_ptr);

    uarf_assert(snip);

    switch (snip->type) {
    case VSNIP_ALIGN: {
        while (uarf_vsnip_align_alloc(&snip->vsnip_align, &stub->end_addr,
                                      uarf_stub_size_free(stub)) == -ENOSPC) {
            uarf_stub_extend(stub);
        }
        break;
    }
    case VSNIP_ASSERT_ALIGN: {
        uarf_vsnip_assert_align_alloc(&snip->vsnip_assert_align, stub);
        break;
    }
    case VSNIP_DUMP_STUB: {
        uarf_vsnip_dump_stub_alloc(&snip->vsnip_dump_stub, stub);
        break;
    }
    case VSNIP_JMP_NEAR_ABS: {
        while (uarf_vsnip_jmp_near_abs_alloc(&snip->vsnip_jmp_near_abs, &stub->end_addr,
                                             uarf_stub_size_free(stub)) == -ENOSPC) {
            uarf_stub_extend(stub);
        }
        break;
    }
    case VSNIP_JMP_NEAR_REL: {
        while (uarf_vsnip_jmp_near_rel_alloc(&snip->vsnip_jmp_near_rel, &stub->end_addr,
                                             uarf_stub_size_free(stub)) == -ENOSPC) {
            uarf_stub_extend(stub);
        }
        break;
    }
    case VSNIP_FILL: {
        while (uarf_vsnip_fill_alloc(&snip->vsnip_fill, &stub->end_addr,
                                     uarf_stub_size_free(stub)) == -ENOSPC) {
            uarf_stub_extend(stub);
        }
        break;
    }
    default: {
        UARF_LOG_WARNING("%d is invalid\n", snip->type);
        uarf_bug();
    }
    }
}

void uarf_jita_allocate(UarfJitaCtxt *ctxt, UarfStub *stub, uint64_t addr) {
    UARF_LOG_TRACE("(%p, %p, %lx)\n", ctxt, stub, addr);

    uarf_assert(ctxt);
    uarf_assert(stub);

    uarf_assert(addr);

    // Assert stub has not been allocated
    uarf_assert(stub->size == 0);

    stub->base_addr = ALIGN_DOWN(addr, PAGE_SIZE);
    stub->size = 0;
    stub->addr = addr;
    stub->end_addr = addr;

    if (ctxt->n_snips == 0) {
        UARF_LOG_WARNING("No stubs have been added to the jita!\nIs this really "
                         "what you want?\n");
    }

    UARF_LOG_DEBUG("Create new stub with:\n"
                   "\tbase_addr: 0x%lx\n\taddr: 0x%lx\n\tend_addr: 0x%lx\n",
                   stub->base_addr, stub->addr, stub->end_addr);

    UARF_LOG_DEBUG("There are %lu snippets to allocate\n", ctxt->n_snips);

    for (size_t i = 0; i < ctxt->n_snips; i++) {
        UarfSnip *snip = &ctxt->snips[i];
        switch (snip->type) {
        case VSNIP:
            _uarf_allocate_vsnip(ctxt, stub, &snip->vsnip);
            break;
        case PSNIP:
            _uarf_allocate_psnip(ctxt, stub, snip->psnip);
            break;
        default:
            uarf_bug();
        }
    }

    return;
}

void uarf_jita_deallocate(UarfJitaCtxt *ctxt, UarfStub *stub) {
    UARF_LOG_TRACE("(%p, %p)\n", ctxt, stub);

    uarf_assert(ctxt);
    uarf_assert(stub);

    uarf_stub_free(stub);
}

void uarf_jita_push_vsnip(UarfJitaCtxt *ctxt, UarfVsnip snip) {
    UARF_LOG_TRACE("(%p, snip)\n", ctxt);

    uarf_assert(ctxt);
    uarf_assert(ctxt->n_snips < JITA_CTXT_MAX_SNIPS - 1);

    ctxt->snips[ctxt->n_snips++] = (UarfSnip) {
        .vsnip = snip,
        .type = VSNIP,
    };

    UARF_LOG_DEBUG("There are now %lu/%d snippets\n", ctxt->n_snips, JITA_CTXT_MAX_SNIPS);
}

void uarf_jita_push_psnip(UarfJitaCtxt *ctxt, UarfPsnip *snip) {
    UARF_LOG_TRACE("(%p, %p)\n", ctxt, snip);
    uarf_assert(snip);
    uarf_assert(snip->ptr);
    uarf_assert(snip->end_ptr);

    uarf_assert(ctxt);
    uarf_assert(ctxt->n_snips < JITA_CTXT_MAX_SNIPS - 1);

    ctxt->snips[ctxt->n_snips++] = (UarfSnip) {
        .psnip = snip,
        .type = PSNIP,
    };
    UARF_LOG_DEBUG("There are now %lu/%d snippets\n", ctxt->n_snips, JITA_CTXT_MAX_SNIPS);
}

void uarf_jita_pop(UarfJitaCtxt *ctxt, UarfSnip *snip) {
    UARF_LOG_TRACE("(%p, %p)\n", ctxt, snip);
    uarf_assert(ctxt);

    // If nothing to pop
    if (!ctxt->n_snips) {
        return;
    }

    // If pop and return
    if (snip) {
        *snip = ctxt->snips[ctxt->n_snips--];
        return;
    }

    // Pop without return
    ctxt->n_snips--;
}

void uarf_jita_clone(UarfJitaCtxt *from, UarfJitaCtxt *to) {
    UARF_LOG_TRACE("(%p, %p)\n", from, to);
    *to = *from;
}

void uarf_jita_push_vsnip_align(UarfJitaCtxt *ctxt, uint32_t align) {
    UARF_LOG_TRACE("(%p, %d)\n", ctxt, align);
    uarf_assert(ctxt);
    uarf_assert(align > 0);

    UarfVsnip align_snip = (UarfVsnip) {
        .type = VSNIP_ALIGN,
        .vsnip_align = (UarfVsnipAlign) {.alignment = align},
    };
    uarf_jita_push_vsnip(ctxt, align_snip);
}

void uarf_jita_push_vsnip_assert_align(UarfJitaCtxt *ctxt, uint32_t alignment) {
    UARF_LOG_TRACE("(%p, %u)\n", ctxt, alignment);
    uarf_assert(ctxt);

    UarfVsnip assert_snip = (UarfVsnip) {
        .type = VSNIP_ASSERT_ALIGN,
        .vsnip_assert_align = (UarfVsnipAssertAlign) {.alignment = alignment},
    };
    uarf_jita_push_vsnip(ctxt, assert_snip);
}

void uarf_jita_push_vsnip_dump_stub(UarfJitaCtxt *ctxt, UarfStub *dump_to) {
    UARF_LOG_TRACE("(%p, %p)\n", ctxt, dump_to);
    uarf_assert(ctxt);
    uarf_assert(dump_to);

    UarfVsnip dump_stub_snip = (UarfVsnip) {
        .type = VSNIP_DUMP_STUB,
        .vsnip_dump_stub = (UarfVsnipDumpStub) {.dump_to = dump_to},
    };
    uarf_jita_push_vsnip(ctxt, dump_stub_snip);
}

void uarf_jita_push_vsnip_jmp_near_abs(UarfJitaCtxt *ctxt, uint64_t target_addr) {
    UARF_LOG_TRACE("(%p, 0x%lx)\n", ctxt, target_addr);

    uarf_assert(ctxt);

    UarfVsnip jmp_dir_snip = (UarfVsnip) {
        .type = VSNIP_JMP_NEAR_ABS,
        .vsnip_jmp_near_abs = (UarfVsnipJmpNearAbs) {.target_addr = target_addr},
    };
    uarf_jita_push_vsnip(ctxt, jmp_dir_snip);
}

void uarf_jita_push_vsnip_jmp_near_rel(UarfJitaCtxt *ctxt, uint32_t offset,
                                       bool inclusive) {
    UARF_LOG_TRACE("(%p, 0x%x, %b)\n", ctxt, offset, inclusive);

    uarf_assert(ctxt);

    // Compensate for the jmp instruction size of required
    uarf_assert(!inclusive || offset >= 5);
    uint32_t off = inclusive ? offset - 5 : offset;
    UARF_LOG_DEBUG("Adjust offset to %u\n", off);

    UarfVsnip jmp_dir_snip = (UarfVsnip) {
        .type = VSNIP_JMP_NEAR_REL,
        .vsnip_jmp_near_rel = (UarfVsnipJmpNearRel) {.offset = off},
    };
    uarf_jita_push_vsnip(ctxt, jmp_dir_snip);
}

void uarf_jita_push_vsnip_fill_nop(UarfJitaCtxt *ctxt, uint32_t num) {
    UARF_LOG_TRACE("(%p, %u)\n", ctxt, num);
    uarf_assert(ctxt);

    UarfVsnip fill_snip = (UarfVsnip) {
        .type = VSNIP_FILL,
        .vsnip_fill =
            (Uarf_VsnipFill) {
                .bytes = {0x90},
                .size = 1,
                .times = num,
            },
    };
    uarf_jita_push_vsnip(ctxt, fill_snip);
}
