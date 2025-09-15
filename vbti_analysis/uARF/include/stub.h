/*
 * Represents executable code. Derived from a jita.
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

/**
 * Executable code, starting at addr
 */
typedef struct UarfStub UarfStub;
struct UarfStub {
    // Start of allocated memory, aligned to the (initial) size of the allocated memory
    // region
    union {
        char *base_ptr;
        uint64_t base_addr;
    };
    // Size of allocated memory
    size_t size;

    // Start of stub code
    union {
        char *ptr;
        uint64_t addr;
        void (*f)(void);
    };

    // End of stub, incremented as new snippets are added
    union {
        char *end_ptr;
        uint64_t end_addr;
    };
};

/**
 * Get an initialized stub_t.
 *
 * Only required in local function, as globals are initialized to zero.
 */
static __always_inline UarfStub uarf_stub_init(void) {
    return (UarfStub) {.size = 0};
}

/**
 * Add `size` bytes of code at addr `start` to `stub`.
 */
void uarf_stub_add(UarfStub *stub, uint64_t start, uint64_t size);

/**
 * Map more memory at contiguous addresses for the stub
 */
void uarf_stub_extend(UarfStub *stub);

/**
 * Frees all memory used by the stub
 */
void uarf_stub_free(UarfStub *stub);

/**
 * Number of bytes that are free.
 */
uint64_t uarf_stub_size_free(UarfStub *stub);
