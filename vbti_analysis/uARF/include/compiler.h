#pragma once

#ifndef __ASSEMBLY__
#include <stdint.h>
#endif

#ifndef _STR
#define _STR(x) #x
#endif
#ifndef STR
#define STR(x) _STR(x)
#endif

#ifndef CAT_
#define CAT_(a, b, c, d, e, f, g, i, j, k, l, m, n, o, p, ...)                           \
    a##b##c##d##e##f##g##i##j##k##l##m##n##o##p
#endif

// Concatenate arbitrarily many token (max 16)
#ifndef CAT
#define CAT(...) CAT_(__VA_ARGS__, , , , , , , , , , , , , , , , , )
#endif

#ifdef __ASSEMBLY__
#ifndef _INTEGER
#define _INTEGER(num, suffix) num
#endif
#else
#ifndef _INTEGER
#define _INTEGER(num, suffix) CAT(num, suffix)
#endif
#endif

#ifndef _U32
#define _U32(x) _INTEGER(x, U)
#endif
#ifndef _U64
#define _U64(x) _INTEGER(x, ULL)
#endif

#ifndef __ASSEMBLY__
#ifndef _ptr
#define _ptr(val) ((void *) (unsigned long) (val))
#endif
#ifndef _ul
#define _ul(val) ((unsigned long) (val))
#endif
#ifndef _u
#define _u(val) ((unsigned int) (val))
#endif
#ifndef _int
#define _int(val) ((int) (val))
#endif
#endif

#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#ifndef __packed
#define __packed __attribute__((__packed__))
#endif
#ifndef __section
#define __section(s) __attribute__((__section__(s)))
#endif
#ifndef __noinline
#define __noinline __attribute__((__noinline__))
#endif

#ifndef __text
#define __text __section(".text")
#endif
#ifndef __data
#define __data __section(".data")
#endif

#ifndef __user_text
#define __user_text __section(".text.user")
#endif
#ifndef __user_data
#define __user_data __section(".data.user")
#endif

#ifndef __ASSEMBLY__
// A one-bit mask at bit n of type t
#ifndef BIT_T
#define BIT_T(t, n) ((t) 1 << (n))
#endif

// A one-bit mask at bit n
#ifndef BIT
#define BIT(n) BIT_T(uint64_t, n)
#endif

// Set bit at index `bit` in `value` to 1
#ifndef BIT_SET
#define BIT_SET(value, bit) ((value) | BIT(bit))
#endif

// Set bit at index `bit` in `value` to 0
#ifndef BIT_CLEAR
#define BIT_CLEAR(value, bit) ((value) & ~BIT(bit))
#endif

// Align an address, rounding the address down
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(addr, align) ((_ul(addr)) & ~((_ul(align)) - 1))
#endif

// Align an address, rounding the address up
#ifndef ALIGN_UP
#define ALIGN_UP(addr, align) (((_ul(addr)) + ((_ul(align)) - 1)) & ~((_ul(align)) - 1))
#endif

// Is the number a power of two (larger than 0)?
#ifndef IS_POW_TWO
#define IS_POW_TWO(num) ((num & (num - 1)) == 0)
#endif

#endif
