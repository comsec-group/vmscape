#include "pfc.h"
#include "lib.h"
#include <err.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

int uarf_pfc_init(UarfPfc *pfc, uint64_t config) {
    UARF_LOG_TRACE("(%p, %lu)\n", pfc, config);
    memset(pfc, 0, sizeof(UarfPfc));
    pfc->config = config;

    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_RAW;
    pe.size = sizeof(pe);
    pe.config = pfc->config;
    pe.config1 = pfc->config1;
    pe.config2 = pfc->config2;
    // pe.config3 = pfc->config3;
    pe.sample_type = PERF_SAMPLE_CPU | PERF_SAMPLE_RAW;
    // pe.disabled = 1;
    // pe.exclude_user = 1;
    // pe.exclude_kernel = 1;
    // pe.exclude_hv = 1;
    pe.exclude_idle = 1;
    // pe.exclude_host = 1;
    // pe.exclude_guest = 1;
    pe.exclude_callchain_kernel = 1;

    pfc->fd = uarf_perf_event_open(&pe, 0, -1, -1, 0);
    if (pfc->fd == -1) {
        UARF_LOG_ERROR("Error opening PFC %llx\nDo you run as root?\n", pe.config);
        exit(1);
    }

    pfc->page = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, pfc->fd, 0);
    if (!pfc->page->cap_user_rdpmc) {
        UARF_LOG_WARNING("rdpmc is not available!\n");
    }

    // TODO: why have to subtract 1?
    pfc->index = pfc->page->index - 1;
    pfc->offset = pfc->page->offset;
    pfc->mask = (1ul << pfc->page->pmc_width) - 1;

    return 0;
}

void uarf_pfc_deinit(UarfPfc *pfc) {
    UARF_LOG_TRACE("(%p)\n", pfc);
    munmap(pfc->page, 0x1000);
    close(pfc->fd);
    pfc->page = 0;
    pfc->fd = 0;
}

uint64_t uarf_pfc_read(UarfPfc *pfc) {
    UARF_LOG_TRACE("(%p)\n", pfc);
    // TODO: Do I need locks?
    uint64_t pmc = uarf_rdpmc(pfc->index);
    UARF_LOG_DEBUG("raw PFC value: %lu\n", pmc);
    return uarf_pm_transform_raw2(pfc, pmc);
}
