#pragma once
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

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
    uint16_t port;
};

typedef struct UarfPiReqOuts UarfPiReqOuts;
struct UarfPiReqOuts {
    char *buf;
    size_t len;
    uint16_t port;
};

static int fd_pi;

static __always_inline void uarf_pi_init(void) {
    fd_pi = open("/dev/pi", O_RDONLY, 0777);
    if (fd_pi == -1) {
        printf("uarf_pi module missing");
    }
}

static __always_inline int uarf_pi_deinit(void) {
    return close(fd_pi);
}

static __always_inline uint64_t uarf_pi_rdmsr(uint32_t msr) {
    UarfPiReqMsr req = {.msr = msr};

    if (ioctl(fd_pi, UARF_IOCTL_RDMSR, &req) < 0) {
        perror("Failed to read MSR\n");
        return -1;
    }

    return req.value;
}

static __always_inline void uarf_pi_wrmsr(uint32_t msr, uint64_t value) {
    UarfPiReqMsr req = {.msr = msr, .value = value};

    if (ioctl(fd_pi, UARF_IOCTL_WRMSR, &req) < 0) {
        perror("Failed to write MSR\n");
    }
}

static __always_inline void uarf_pi_invlpg(uint64_t addr) {
    uint64_t a = addr;
    if (ioctl(fd_pi, UARF_IOCTL_INVLPG, &a) < 0) {
        perror("Failed to invalidate TLB for addr\n");
    }
}

static __always_inline void uarf_pi_flush_tlb(void) {
    if (ioctl(fd_pi, UARF_IOCTL_FLUSH_TLB, NULL) < 0) {
        perror("Failed to flush TLB\n");
    }
}

static __always_inline void uarf_pi_cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                                          uint32_t *ecx, uint32_t *edx) {

    UarfPiReqCpuid req = {.eax = leaf, .ebx = 0, .ecx = 0, .edx = 0};

    if (ioctl(fd_pi, UARF_IOCTL_CPUID, &req) < 0) {
        perror("Failed to CPUID\n");
    }

    if (eax) {
        *eax = req.eax;
    }
    if (ebx) {
        *ebx = req.ebx;
    }
    if (ecx) {
        *ecx = req.ecx;
    }
    if (edx) {
        *edx = req.edx;
    }
}

static __always_inline void uarf_pi_vmmcall(uint32_t nr) {
    uint32_t a = nr;
    if (ioctl(fd_pi, UARF_IOCTL_VMMCALL, &a) < 0) {
        perror("Failed to vmmcall\n");
    }
}

static __always_inline void uarf_pi_out(uint32_t value, uint16_t port) {
    UarfPiReqOut req = {.value = value, .port = port};
    if (ioctl(fd_pi, UARF_IOCTL_OUT, &req) < 0) {
        perror("Failed to out\n");
    }
}

static __always_inline void uarf_pi_outs(char *buf, size_t len, uint16_t port) {
    UarfPiReqOuts req = {.buf = buf, .len = len, .port = port};
    if (ioctl(fd_pi, UARF_IOCTL_OUTS, &req) < 0) {
        perror("Failed to outs\n");
    }
}
