/**
 * Guest Flush Reload
 *
 * How is the flush and reload functionality used from guest to host and host to guest?
 */

#include "uarf/flush_reload.h"
#include "uarf/jita.h"
#include "uarf/kmod/pi.h"
#include "uarf/kmod/rap.h"
#include "uarf/lib.h"
#include "uarf/log.h"
#include "uarf/spec_lib.h"
#include "uarf/test.h"

#include <ucall_common.h>

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG LOG_TAG_TEST
#endif

#define SECRET    3
#define NUM_RUNDS 10

struct GuestData {
    struct FrConfig fr_config;
    uint64_t secret;
};

// Out globals that we also need in our guest
struct GuestData guestData;

static void access_fr_global(void) {
    fr_flush(&guestData.fr_config);
    mfence();
    lfence();

    // Runs the flush and reload side channel in kernel
    *(volatile uint8_t *) (guestData.fr_config.buf.addr + guestData.secret * FR_STRIDE);
    *(volatile uint8_t *) (guestData.fr_config.buf.addr +
                           (guestData.secret + 2) * FR_STRIDE);
}

static void guest_main(void) {
    GUEST_PRINTF("Guest started\n");

    access_fr_global();

    GUEST_PRINTF("Spec done\n");
    GUEST_DONE();
}

// TODO: Move to helper
void map_mem_to_guest(struct kvm_vm *vm, uint64_t va, uint64_t size) {
    LOG_TRACE("(vm: %p, va: 0x%lx, size: %lu)\n", vm, va, size);
    static uint64_t next_slot = NR_MEM_REGIONS;
    static uint64_t used_pages = 0;

    uint64_t va_aligned = ALIGN_DOWN(va, PAGE_SIZE);
    LOG_DEBUG("Aligned 0x%lx to 0x%lx\n", va, va_aligned);

    uint64_t num_pages_to_map = DIV_ROUND_UP(size, PAGE_SIZE);
    uint64_t gpa = (vm->max_gfn - used_pages - num_pages_to_map) * PAGE_SIZE;

    LOG_DEBUG("Add %lu pages (required: %lu B) of physical memory to guest at gpa 0x%lx "
              "(slot %lu)\n",
              num_pages_to_map, size, gpa, next_slot);
    vm_userspace_mem_region_add(vm, DEFAULT_VM_MEM_SRC, gpa, next_slot, num_pages_to_map,
                                0);

    LOG_DEBUG("Add mapping in guest for gpa 0x%lx to gva 0x%lx\n", gpa, va_aligned);
    virt_map(vm, va_aligned, gpa, num_pages_to_map);
    used_pages += num_pages_to_map;
    next_slot++;

    uint64_t *addr = addr_gpa2hva(vm, (vm_paddr_t) gpa);
    LOG_DEBUG("Copy %lu bytes from 0x%lx to 0x%lx\n", size, va, _ul(addr));
    memcpy(addr, _ptr(va), size);
}

// TODO: Move to helper
static void run_vcpu(struct kvm_vcpu *vcpu) {
    LOG_TRACE("(vcpu: %p)\n", vcpu);
    struct ucall uc;

    while (true) {
        vcpu_run(vcpu);

        switch (get_ucall(vcpu, &uc)) {
        case UCALL_SYNC:
            return;
        case UCALL_DONE:
            return;
        case UCALL_ABORT:
            REPORT_GUEST_ASSERT(uc);
        case UCALL_PRINTF:
            // allow the guest to print debug information
            printf("guest | %s", uc.buffer);
            break;
        default:
            TEST_FAIL("Unhandled ucall: %ld\nexit_reason: %u (%s)", uc.cmd,
                      vcpu->run->exit_reason, exit_reason_str(vcpu->run->exit_reason));
        }
    }
}

static inline void access_fr_host(struct FrConfig *fr, uint64_t secret) {
    guestData.fr_config = *fr;
    guestData.secret = secret;
    access_fr_global();
}

static void access_fr_guest(struct FrConfig *fr, uint64_t secret) {
    struct kvm_vcpu *vcpu;
    struct kvm_vm *vm;

    uint64_t extra_pages = 10 * (3 + 512);

    guestData.fr_config = *fr;
    guestData.secret = secret;

    // Create VM
    vm = __vm_create_with_one_vcpu(&vcpu, extra_pages, guest_main);

    // Sync globals
    sync_global_to_guest(vm, guestData);

    // Map other memory
    map_mem_to_guest(vm, fr->buf.base_addr, fr->buf_size);
    // map_mem_to_guest(vm, fr->buf2.base_addr, fr->buf_size);
    map_mem_to_guest(vm, fr->res_addr, fr->res_size);

    // Run VM
    run_vcpu(vcpu);

    // Trash VM (TODO: recycle VM somehow)
    kvm_vm_free(vm);
}

// Access fr in host, reload in host (basecase)
TEST_CASE(flush_reload_host_host) {
    struct FrConfig fr = fr_init(8, 1, NULL);
    fr_reset(&fr);

    for (size_t i = 0; i < NUM_RUNDS; i++) {
        fr_flush(&fr);

        access_fr_host(&fr, SECRET);

        fr_reload(&fr);
    }

    LOG_DEBUG("FR Buffer\n");
    fr_print(&fr);

    fr_deinit(&fr);

    TEST_PASS();
}

// Access fr in guest, reload in host
TEST_CASE(flush_reload_guest_host) {
    struct kvm_vcpu *vcpu;
    struct kvm_vm *vm;

    uint64_t extra_pages = 10 * (3 + 512);

    struct FrConfig fr = fr_init(8, 1, NULL);
    fr_reset(&fr);

    guestData.fr_config = fr;
    guestData.secret = SECRET;

    for (size_t i = 0; i < NUM_RUNDS; i++) {
        // Create VM
        vm = __vm_create_with_one_vcpu(&vcpu, extra_pages, guest_main);

        // Sync globals
        sync_global_to_guest(vm, guestData);

        // Map other memory
        map_mem_to_guest(vm, fr.buf.base_addr, fr.buf_size);
        map_mem_to_guest(vm, fr.res_addr, fr.res_size);

        fr.buf.handle_p = addr_gva2hva(vm, fr.buf.addr);

        fr_flush(&fr);

        // Run VM
        if (i % 2) {
            run_vcpu(vcpu);
        }

        // Reload before destroying VM
        fr_reload(&fr);

        // Trash VM (TODO: recycle VM somehow)
        kvm_vm_free(vm);
    }

    LOG_DEBUG("FR Buffer\n");
    fr_print(&fr);

    fr_deinit(&fr);

    TEST_PASS();
}

TEST_SUITE() {
    // log_system_level = LOG_LEVEL_INFO;
    RUN_TEST_CASE(flush_reload_host_host, "Host -> Host");
    RUN_TEST_CASE(flush_reload_guest_host, "Guest -> Host");

    return 0;
}
