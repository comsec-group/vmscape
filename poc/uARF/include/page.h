#pragma once

#include "compiler.h"

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE (_U64(1) << PAGE_SHIFT)
#endif

#ifndef PAGE_SHIFT_2M
#define PAGE_SHIFT_2M 21
#endif

#ifndef PAGE_SIZE_2M
#define PAGE_SIZE_2M (_U64(1) << PAGE_SHIFT_2M)
#endif

#ifndef PAGE_SHIFT_1G
#define PAGE_SHIFT_1G 30
#endif

#ifndef PAGE_SIZE_1G
#define PAGE_SIZE_1G (_U64(1) << PAGE_SHIFT_1G)
#endif
