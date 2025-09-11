#pragma once

#include <linux/types.h>

#define UARF_IOCTL_RAP _IOWR('m', 1, UarfRapRequest)

typedef struct UarfRapRequest UarfRapRequest;
struct UarfRapRequest {
    union {
        uint64_t (*func)(void *);
        void *ptr;
        uint64_t addr;
    };
    void *data;
    uint64_t return_data;
};
