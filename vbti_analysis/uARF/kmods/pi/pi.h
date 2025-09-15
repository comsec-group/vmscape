#pragma once

#include <linux/types.h>

#define UARF_IOCTL_RDMSR     _IOWR('m', 1, UarfPiReqMsr)
#define UARF_IOCTL_WRMSR     _IOWR('m', 2, UarfPiReqMsr)
#define UARF_IOCTL_INVLPG    _IOWR('m', 3, uint64_t)
#define UARF_IOCTL_FLUSH_TLB _IOWR('m', 4, uint64_t)
#define UARF_IOCTL_CPUID     _IOWR('m', 5, UarfPiReqCpuid)
#define UARF_IOCTL_VMMCALL   _IOWR('m', 6, uint32_t)
#define UARF_IOCTL_OUT       _IOWR('m', 7, UarfPiReqOut)
#define UARF_IOCTL_OUTS      _IOWR('m', 8, UarfPiReqOuts)

// For rdmsr/rwmsr
typedef struct UarfPiReqMsr UarfPiReqMsr;
struct UarfPiReqMsr {
    uint32_t msr;
    uint64_t value;
};

typedef struct UarfPiReqCpuid UarfPiReqCpuid;
struct UarfPiReqCpuid {
    uint32_t eax; // Leaf
    uint32_t ebx;
    uint32_t ecx; // Sub-leaf
    uint32_t edx;
};

typedef struct UarfPiReqOut UarfPiReqOut;
struct UarfPiReqOut {
    uint32_t value;
    uint32_t port;
};

typedef struct UarfPiReqOuts UarfPiReqOuts;
struct UarfPiReqOuts {
    char *buf;
    size_t len;
    uint16_t port;
};
