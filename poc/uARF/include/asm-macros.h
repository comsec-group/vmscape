#pragma once

#ifdef __ASSEMBLY__

#define GLOBAL(name)                                                                     \
    .global name;                                                                        \
    name:

#define ENTRY(name)                                                                      \
    .align 16;                                                                           \
    GLOBAL(name)

#define SECTION(name, flags, alignment)                                                  \
    .section name, flags;                                                                \
    .align alignment

#define SIZE(name) .size name, (.- name);

#endif // __ASSEMBLY__
