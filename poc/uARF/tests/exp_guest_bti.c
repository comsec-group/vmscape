/*
 * Automatic IBRS BTI on Guest
 *
 * That is the impact of Automatic IBRS on BTI considering the guest? Is is
 * still possible?
 *
 * As the attack vector we consider all combinations of HU, HS, GS, but as of
 * now, no GU.
 *
 * We test the mentioned attack vectos, toggle autoIBRS to see its impact. The
 * results of this experiment are summarized in this table:
 *
 * ## For Zen4
 *
 * ### For jmp:
 *
 * tr \ sig |      HU     |      HS     |      GU     |      GS     |
 * autoIBRS |   no ! yes  |   no ! yes  |   no ! yes  |   no ! yes  |
 * -------- | ----------- | ----------- | ----------- | ----------- |
 *       HU | 1.00 ! 1.00 | 1.00 ! 0.00 | 1.00 ! 1.00 | 1.00 ! 0.00 |
 *       HS | 1.00 ! 1.00 | 1.00 ! 0.00 | 1.00 ! 1.00 | 1.00 ! 0.00 |
 *       GU | 1.00 ! 1.00 | 1.00 ! 0.00 | 1.00 ! 1.00 | 1.00 ! 0.00 |
 *       GS | 1.00 ! 1.00 | 1.00 ! 0.00 | 1.00 ! 1.00 | 1.00 ! 0.00 |
 *
 * tr \ sig |   HU  |   HS  |   GU  |   GS  |
 * autoIBRS | n ! y | n ! y | n ! y | n ! y |
 * -------- | ----- | ----- | ----- | ----- |
 *       HU | X ! X | X ! _ | X ! X | X ! _ |
 *       HS | X ! X | X ! _ | X ! X | X ! _ |
 *       GU | X ! X | X ! _ | X ! X | X ! _ |
 *       GS | X ! X | X ! _ | X ! X | X ! _ |
 *
 * Neither user and supervisor, nor host and guest are separated in way.
 * autoIBRS is required to protect host/guest supervisor from host/guest user.
 * There is no difference between guest and host.
 *
 * ### For call:
 *
 * tr \ sig |      HU     |      HS     |      GU     |      GS     |
 * autoIBRS |   no ! yes  |   no ! yes  |   no ! yes  |   no ! yes  |
 * -------- | ----------- | ----------- | ----------- | ----------- |
 *       HU | 1.00 ! 1.00 | 1.00 ! 0.00 | 1.00 ! 1.00 | 1.00 ! 0.00 |
 *       HS | 1.00 ! 1.00 | 1.00 ! 0.00 | 1.00 ! 1.00 | 1.00 ! 0.00 |
 *       GU | 1.00 ! 1.00 | 1.00 ! 0.00 | 1.00 ! 1.00 | 1.00 ! 0.00 |
 *       GS | 1.00 ! 1.00 | 1.00 ! 0.00 | 1.00 ! 1.00 | 1.00 ! 0.00 |
 *
 * Same as for jmp
 *
 *
 * ## For Zen5
 *
 * ### For jmp:
 *
 * tr \ sig |      HU     |      HS     |      GU     |      GS     |
 * autoIBRS |   no ! yes  |   no ! yes  |   no ! yes  |   no ! yes  |
 * -------- | ----------- | ----------- | ----------- | ----------- |
 *       HU | 1.00 ! 1.00 | 0.00 ! 0.00 | 1.00 ! 1.00 | 0.00 ! 0.00 |
 *       HS | 0.00 ! 0.00 | 1.00 ! 0.00 | 0.00 ! 0.00 | 1.00 ! 0.00 |
 *       GU | 1.00 ! 1.00 | 0.00 ! 0.00 | 1.00 ! 1.00 | 0.00 ! 0.00 |
 *       GS | 0.00 ! 0.00 | 1.00 ! 0.00 | 0.00 ! 0.00 | 1.00 ! 0.00 |
 *
 * tr \ sig |   HU  |   HS  |   GU  |   GS  |
 * autoIBRS | n ! y | n ! y | n ! y | n ! y |
 * -------- | ----- | ----- | ----- | ----- |
 *       HU | X ! X | _ ! _ | X ! X | _ ! _ |
 *       HS | _ ! _ | X ! _ | _ ! _ | X ! _ |
 *       GU | X ! X | _ ! _ | X ! X | _ ! _ |
 *       GS | _ ! _ | X ! _ | _ ! _ | X ! _ |
 *
 * User and supervisor are clearly separated, as under no circumstance we get
 * any signal between the two modes. autoIBRS is not required to protect
 * host/guest supervisor from host/guest user. However, is is required to
 * protect host supervisor from guest supervisor, and vice versa. The is no
 * difference between guest and host.
 *
 *
 * ### For call:
 *
 * tr \ sig |      HU     |      HS     |      GU     |      GS     |
 * autoIBRS |   no ! yes  |   no ! yes  |   no ! yes  |   no ! yes  |
 * -------- | ----------- | ----------- | ----------- | ----------- |
 *       HU | 1.00 ! 1.00 | 0.00 ! 0.00 | 1.00 ! 1.00 | 0.00 ! 0.00 |
 *       HS | 0.00 ! 0.00 | 1.00 ! 0.00 | 0.00 ! 0.00 | 1.00 ! 0.00 |
 *       GU | 1.00 ! 1.00 | 0.00 ! 0.00 | 1.00 ! 1.00 | 0.00 ! 0.00 |
 *       GS | 0.00 ! 0.00 | 1.00 ! 0.00 | 0.00 ! 0.00 | 1.00 ! 0.00 |
 *
 * Same as for jmp
 */

#include "processor.h"
#include <ucall_common.h>

#include "uarf/flush_reload_static.h"
#include "uarf/guest.h"
#include "uarf/jita.h"
#include "uarf/kmod/pi.h"
#include "uarf/kmod/rap.h"
#include "uarf/lib.h"
#include "uarf/log.h"
#include "uarf/spec_lib.h"
#include "uarf/test.h"

#define ERRNO_GENERAL          1
#define ERRNO_INVALID_ARGUMENT 2
#define ERRNO_VM               3

#define SECRET 5

// Ealuation mode enable
//  - Continuously dump results
//  - Instant quit on error
// #define IN_EVALUATION_MODE
static bool IN_EVALUATION_MODE = false;

#ifdef UARF_LOG_TAG
#undef UARF_LOG_TAG
#define UARF_LOG_TAG UARF_LOG_TAG_TEST
#endif

#define CREATE_TCD(t_mode, s_mode, a_ibrs, main_jita)                                    \
    (struct TestCaseData) {                                                              \
        .seed = seed++, .num_cands = 100, .num_rounds = 10, .num_train_rounds = 1,       \
        .jita_main = &main_jita, .jita_gadget = &jita_gadget, .jita_dummy = &jita_dummy, \
        .match_history = true, .train_mode = t_mode, .signal_mode = s_mode,              \
        .autoibrs_off = a_ibrs,                                                          \
    }

uarf_psnip_declare(history, psnip_history);
uarf_psnip_declare(src_call_ind_no_ret, psnip_src_call_ind);
uarf_psnip_declare(src_jmp_ind_no_ret, psnip_src_jmp_ind);
uarf_psnip_declare(src_ret_no_ret, psnip_src_ret);
uarf_psnip_declare(dst_gadget, psnip_dst_gadget);
uarf_psnip_declare(dst_dummy, psnip_dst_dummy);

uarf_psnip_declare_define(psnip_ret, "ret\n\t");

enum RunMode {
    RUN_MODE_HOST_USER,
    RUN_MODE_HOST_SUPERVISOR,
    RUN_MODE_GUEST_USER,
    RUN_MODE_GUEST_SUPERVISOR,
    RUN_MODE_GUEST2_USER,
    RUN_MODE_GUEST2_SUPERVISOR,
    RUN_MODE_NONE, // For SMT, when only doing training or signaling
};

const char *MODE_STR[6] = {
    "HU", "HS", "GU", "GS", "G2U", "G2S",
};

enum RunMode get_mode_from_string(char *mode) {
    UARF_LOG_TRACE("(%s)\n", mode);
    if (strcmp(mode, MODE_STR[RUN_MODE_HOST_USER]) == 0) {
        return RUN_MODE_HOST_USER;
    }
    if (strcmp(mode, MODE_STR[RUN_MODE_HOST_SUPERVISOR]) == 0) {
        return RUN_MODE_HOST_SUPERVISOR;
    }
    if (strcmp(mode, MODE_STR[RUN_MODE_GUEST_USER]) == 0) {
        return RUN_MODE_GUEST_USER;
    }
    if (strcmp(mode, MODE_STR[RUN_MODE_GUEST_SUPERVISOR]) == 0) {
        return RUN_MODE_GUEST_SUPERVISOR;
    }
    if (strcmp(mode, MODE_STR[RUN_MODE_GUEST2_USER]) == 0) {
        return RUN_MODE_GUEST2_USER;
    }
    if (strcmp(mode, MODE_STR[RUN_MODE_GUEST2_SUPERVISOR]) == 0) {
        return RUN_MODE_GUEST2_SUPERVISOR;
    }
    UARF_LOG_ERROR("Invalid mode\n");
    exit(ERRNO_INVALID_ARGUMENT);
}

bool mode_in_guest(enum RunMode mode) {
    switch (mode) {
    case RUN_MODE_GUEST_USER:
    case RUN_MODE_GUEST_SUPERVISOR:
        return true;
    default:
        return false;
    }
}

bool mode_in_guest2(enum RunMode mode) {
    switch (mode) {
    case RUN_MODE_GUEST2_USER:
    case RUN_MODE_GUEST2_SUPERVISOR:
        return true;
    default:
        return false;
    }
}

/**
 * Settings that AutoIBRS/eIBRS can have
 */
enum MitSet { MIT_SET_TURN_OFF, MIT_SET_TURN_ON, MIT_SET_DONT_CHANGE };

enum MitSet get_mitset_from_string(char *mode) {
    UARF_LOG_TRACE("(mode: %s)\n", mode);
    if (strcmp(mode, "0") == 0) {
        return MIT_SET_TURN_OFF;
    }
    if (strcmp(mode, "1") == 0) {
        return MIT_SET_TURN_ON;
    }
    UARF_LOG_ERROR("Invalid mitset\n");
    exit(ERRNO_INVALID_ARGUMENT);
}

enum SmtMode { SMT_MODE_TRAIN, SMT_MODE_SIGNAL, SMT_MODE_OFF };

struct TestCaseData {
    uint32_t seed;
    uint32_t num_cands;
    uint32_t num_rounds;
    uint32_t num_train_rounds;
    UarfJitaCtxt *jita_main;
    UarfJitaCtxt *jita_gadget;
    UarfJitaCtxt *jita_dummy;
    bool match_history;
    enum RunMode train_mode;
    enum RunMode signal_mode;
    enum MitSet autoibrs;
    enum MitSet eibrs;
    bool ibrs;
    bool fp_test;
    bool fn_test;
    bool guest_interleave; // Run another guest in-between training and signaling
    enum SmtMode smt;
};

struct GuestData {
    UarfSpecData spec_data;
};

// Globals that we also need in our guest
struct GuestData guest_data;

UarfStub stub_main;
UarfStub stub_gadget;
UarfStub stub_dummy;

/*
 * In contrast to uarf_run_spec this function gets the spec data from a global.
 * This is required for running inside guest. But we can also use this for
 * running on the host.
 */
static void run_spec_global(void) {
    UarfSpecData *data = &guest_data.spec_data;

    // Ensure we have access to the required data
    // It easier to debug if we fail here that later
    // Also prevents page faults, that would hinder the signal
    *(volatile uint64_t *) data->spec_prim_p;
    *(volatile uint64_t *) (_ul(data->spec_prim_p) + PAGE_SIZE);
    **(volatile uint64_t **) data->spec_dst_p_p;
    volatile uint64_t *secret_p = &((uint64_t *) data->fr_buf_p)[data->secret];
    *secret_p;

    *(volatile uint64_t *) stub_main.addr;
    *(volatile uint64_t *) stub_gadget.addr;
    *(volatile uint64_t *) stub_dummy.addr;

    uarf_mfence();
    uarf_lfence();

    // We touched the FR Buffer, so we need to flush again
    uarf_clflush(secret_p);

    asm volatile("lea return_here%=, %%rax\n\t"
                 "pushq %%rax\n\t"
                 "jmp *%0\n\t"
                 "return_here%=:\n\t" ::"r"(data->spec_prim_p),
                 "c"(data)
                 : "rax", "rdx", "rdi", "rsi", "r8", "memory");
}

// Call `uarf_run_spec`, but disable IBRS
static void run_spec_ibrs(void *arg) {
    // Is run as privileged
    uarf_ibrs_on();
    uarf_run_spec(arg);
    uarf_ibrs_off();
}

/**
 * Entry point for running speculation in guest supervisor.
 */
static void guest_run_spec_supervisor(void) {
    run_spec_global();
    GUEST_DONE();
}

/**
 * Entry point for running speculation in guest supervisor, and flush and reload it.
 *
 * For signaling phase.
 */
static void guest_run_fr_spec_supervisor(void) {
    uarf_frs_flush();
    run_spec_global();
    uarf_frs_reload();
    GUEST_DONE();
}

/**
 * Entry point for running speculation in guest user.
 */
static void guest_run_spec_user(void) {
    uarf_init_syscall(uarf_syscall_handler_return, KERNEL_CS, USER_CS_STAR);

    uarf_supervisor2user(USER_DS, USER_CS);
    run_spec_global();

    // Return back to supervisor, such that we do no get troubles when recycling
    // the VM
    uarf_user2supervisor();

    GUEST_DONE();
}

/**
 * Entry point for running speculation in guest user, and flush and reload it.
 *
 * For signaling phase.
 */
static void guest_run_fr_spec_user(void) {
    uarf_init_syscall(uarf_syscall_handler_return, KERNEL_CS, USER_CS_STAR);

    uarf_supervisor2user(USER_DS, USER_CS);

    uarf_frs_flush();
    run_spec_global();
    uarf_frs_reload();

    // Return back to supervisor, such that we do no get troubles when recycling
    // the VM
    uarf_user2supervisor();

    GUEST_DONE();
}

/**
 * Entry point that just returns again.
 */
static void guest_run_cache_measure(void) {
    GUEST_PRINTF("Cache: %lu\n", uarf_get_access_time_cached(1000));
    GUEST_PRINTF("Uncache: %lu\n", uarf_get_access_time_uncached(1000));
    GUEST_DONE();
}

// TODO: Move to helper
void map_mem_to_guest(struct kvm_vm *vm, uint64_t gva, uint64_t size) {
    UARF_LOG_TRACE("(vm: %p, va: 0x%lx, size: %lu)\n", vm, gva, size);
    static uint64_t next_slot = NR_MEM_REGIONS;
    static uint64_t used_pages = 0;

    uint64_t gva_aligned = ALIGN_DOWN(gva, PAGE_SIZE);
    UARF_LOG_DEBUG("Aligned 0x%lx to 0x%lx\n", gva, gva_aligned);

    uint64_t num_pages_to_map = DIV_ROUND_UP(size, PAGE_SIZE);
    uint64_t gpa = (vm->max_gfn - used_pages - num_pages_to_map) * PAGE_SIZE;

    UARF_LOG_DEBUG("Add %lu pages (required: %lu B) of physical memory to guest "
                   "at gpa 0x%lx (slot %lu)\n",
                   num_pages_to_map, size, gpa, next_slot);
    vm_userspace_mem_region_add(vm, DEFAULT_VM_MEM_SRC, gpa, next_slot, num_pages_to_map,
                                0);

    UARF_LOG_DEBUG("Add mapping in guest for gpa 0x%lx to gva 0x%lx\n", gpa, gva_aligned);
    virt_map(vm, gva_aligned, gpa, num_pages_to_map);
    used_pages += num_pages_to_map;
    next_slot++;

    uint64_t *addr = addr_gpa2hva(vm, (vm_paddr_t) gpa);
    UARF_LOG_DEBUG("Copy %lu bytes from 0x%lx to 0x%lx\n", size, gva, _ul(addr));
    memcpy(addr, _ptr(gva), size);
}

// TODO: Move to helper
void map_stub_to_guest(struct kvm_vm *vm, UarfStub *stub) {
    UARF_LOG_TRACE("(vm: %p, stub: %p)\n", vm, stub);
    map_mem_to_guest(vm, stub->base_addr, stub->size);
}

// TODO: Move to helper
static void uarf_guest_run(struct kvm_vcpu *vcpu) {
    struct ucall uc;

    while (true) {
        vcpu_run(vcpu);

        if (IN_EVALUATION_MODE) {
            // Quit on any unexpected VM Exit
            switch (get_ucall(vcpu, &uc)) {
            case UCALL_DONE:
                return;
            default:
                UARF_LOG_ERROR("Got invalid VMEXIT: %s. Exit\n",
                               exit_reason_str(vcpu->run->exit_reason));
                exit(ERRNO_GENERAL);
            }
        }
        else {
            switch (get_ucall(vcpu, &uc)) {
            case UCALL_SYNC:
                printf("Got sync signal\n");
                printf("With %lu arguments\n", uc.args[1]);
                break;
            case UCALL_DONE:
                // printf("Got done signal\n");
                return;
            case UCALL_ABORT:
                printf("Got abort signal\n");
                REPORT_GUEST_ASSERT(uc);
                break;
            case UCALL_PRINTF:
                UARF_LOG_INFO("guest | %s", uc.buffer);
                break;
            case UCALL_NONE:
                printf("Received none, of type: ");
                switch (vcpu->run->exit_reason) {
                case KVM_EXIT_SHUTDOWN:
                    printf("Shutdown\n");
                    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
                    printf("Most likely something went wrong. VM quit\n");
                    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
                    exit(ERRNO_VM);
                    return;
                default:
                    printf("%s\nContinue\n", exit_reason_str(vcpu->run->exit_reason));
                    break;
                }
                break;
            default:
                TEST_ASSERT(false, "Unexpected exit: %s",
                            exit_reason_str(vcpu->run->exit_reason));
            }
        }
    }
}

typedef struct Guest Guest;
struct Guest {
    struct kvm_vcpu *vcpu;
    struct kvm_vm *vm;
};

void setup_guest(Guest *guest, bool signaling) {
    UARF_LOG_TRACE("(guest: %p, signaling: %b)\n", guest, signaling);
    uint64_t extra_pages = 10 * (3 + 512);

    // Target does not matter yet, as we reset it anyways
    guest->vm = __vm_create_with_one_vcpu(&guest->vcpu, extra_pages, guest_run_spec_user);

    // Sync globals
    sync_global_to_guest(guest->vm, guest_data);
    sync_global_to_guest(guest->vm, stub_main);
    sync_global_to_guest(guest->vm, stub_gadget);
    sync_global_to_guest(guest->vm, stub_dummy);

    // Map stubs
    map_stub_to_guest(guest->vm, &stub_main);
    map_stub_to_guest(guest->vm, &stub_gadget);
    map_stub_to_guest(guest->vm, &stub_dummy);

    // Map FR Buffer
    map_mem_to_guest(guest->vm, UARF_FRS_BUF_BASE, UARF_FRS_BUF_SIZE);

    // If signaling is in guest ensure buffer is paged and result buffer mapped
    if (signaling) {
        void *buf_base_hva = addr_gva2hva(guest->vm, UARF_FRS_BUF_BASE);

        // NOTE: Hugepages are apparently supported in KVM selftest guest
        // madvise fails
        // madvise(addr_gva2hva(vm, _ul(buf_base_hva)),
        // 	UARF_FRS_BUF_SIZE, MADV_HUGEPAGE);

        // Ensure it is not zero-page backed
        for (size_t i = 0; i < UARF_FRS_SLOTS; i++) {
            memset(_ptr(buf_base_hva + i * UARF_FRS_STRIDE), '0' + i, UARF_FRS_STRIDE);
        }

        map_mem_to_guest(guest->vm, UARF_FRS_RES, UARF_FRS_RES_SIZE);
        memset(_ptr(addr_gva2hva(guest->vm, UARF_FRS_RES)), 0, UARF_FRS_RES_SIZE);
    }
}

void run_training(struct TestCaseData *data, UarfSpecData *train_data,
                  UarfSpecData *signal_data, Guest *g1, Guest *g2, uint32_t rounds) {
    for (size_t i = 0; i < rounds; i++) {
        switch (data->train_mode) {
        case RUN_MODE_HOST_USER:
            guest_data.spec_data = *train_data;
            run_spec_global();
            break;
        case RUN_MODE_HOST_SUPERVISOR:
            // Ensure the required data is paged, as when executing in supervisor
            // mode we cannot handle pagefaults => error
            *(volatile char *) uarf_run_spec;
            *(volatile char *) train_data->spec_prim_p;
            **(volatile char **) train_data->spec_dst_p_p;
            *(volatile char *) train_data->fr_buf_p;
            *(volatile char *) signal_data->spec_prim_p;
            **(volatile char **) signal_data->spec_dst_p_p;
            *(volatile char *) signal_data->fr_buf_p;

            uarf_rap_call(uarf_run_spec, train_data);
            break;
        case RUN_MODE_GUEST_USER:
            guest_data.spec_data = *train_data;
            sync_global_to_guest(g1->vm, guest_data);

            uarf_guest_set_rip(g1->vcpu, guest_run_spec_user);
            uarf_guest_run(g1->vcpu);
            break;
        case RUN_MODE_GUEST2_USER:
            guest_data.spec_data = *train_data;
            sync_global_to_guest(g2->vm, guest_data);

            uarf_guest_set_rip(g2->vcpu, guest_run_spec_user);
            uarf_guest_run(g2->vcpu);
            break;
        case RUN_MODE_GUEST_SUPERVISOR:
            guest_data.spec_data = *train_data;
            sync_global_to_guest(g1->vm, guest_data);

            uarf_guest_set_rip(g1->vcpu, guest_run_spec_supervisor);
            uarf_guest_run(g1->vcpu);
            break;
        case RUN_MODE_GUEST2_SUPERVISOR:
            guest_data.spec_data = *train_data;
            sync_global_to_guest(g2->vm, guest_data);

            uarf_guest_set_rip(g2->vcpu, guest_run_spec_supervisor);
            uarf_guest_run(g2->vcpu);
            break;
        case RUN_MODE_NONE:
            UARF_LOG_ERROR("Invalid run mode\n");
            uarf_assert(false);
        }
    }
}

void run_signal(struct TestCaseData *data, UarfSpecData *train_data,
                UarfSpecData *signal_data, Guest *g1, Guest *g2) {
    switch (data->signal_mode) {
    case RUN_MODE_HOST_USER:
        uarf_frs_flush();
        guest_data.spec_data = *signal_data;
        run_spec_global();
        *signal_data = guest_data.spec_data;
        uarf_frs_reload();
        break;
    case RUN_MODE_HOST_SUPERVISOR:
        // Ensure the required data is paged, as when executing in supervisor
        // mode we cannot handle page faults => error
        *(volatile char *) uarf_run_spec;
        *(volatile char *) train_data->spec_prim_p;
        **(volatile char **) train_data->spec_dst_p_p;
        *(volatile char *) train_data->fr_buf_p;
        *(volatile char *) signal_data->spec_prim_p;
        **(volatile char **) signal_data->spec_dst_p_p;
        *(volatile char *) signal_data->fr_buf_p;

        *(volatile char *) run_spec_ibrs;
        *(volatile char *) uarf_ibrs_on;
        *(volatile char *) uarf_ibrs_off;

        uarf_frs_flush();
        if (data->ibrs) {
            uarf_rap_call(run_spec_ibrs, signal_data);
        }
        else {
            uarf_rap_call(uarf_run_spec, signal_data);
        }
        uarf_frs_reload();
        break;
    case RUN_MODE_GUEST_USER:
        guest_data.spec_data = *signal_data;
        sync_global_to_guest(g1->vm, guest_data);

        uarf_guest_set_rip(g1->vcpu, guest_run_fr_spec_user);
        uarf_guest_run(g1->vcpu);
        // sync_global_from_guest(vm, guest_data);
        break;
    case RUN_MODE_GUEST2_USER:
        guest_data.spec_data = *signal_data;
        sync_global_to_guest(g2->vm, guest_data);

        uarf_guest_set_rip(g2->vcpu, guest_run_fr_spec_user);
        uarf_guest_run(g2->vcpu);
        // sync_global_from_guest(vm, guest_data);
        break;
    case RUN_MODE_GUEST_SUPERVISOR:
        guest_data.spec_data = *signal_data;
        sync_global_to_guest(g1->vm, guest_data);

        uarf_guest_set_rip(g1->vcpu, guest_run_fr_spec_supervisor);
        uarf_guest_run(g1->vcpu);
        // sync_global_from_guest(vm, guest_data);
        break;
    case RUN_MODE_GUEST2_SUPERVISOR:
        guest_data.spec_data = *signal_data;
        sync_global_to_guest(g2->vm, guest_data);

        uarf_guest_set_rip(g2->vcpu, guest_run_fr_spec_supervisor);
        uarf_guest_run(g2->vcpu);
        // sync_global_from_guest(vm, guest_data);
        break;
    case RUN_MODE_NONE:
        UARF_LOG_ERROR("Invalid run mode\n");
        uarf_assert(false);
    }
}

UARF_TEST_CASE_ARG(basic, arg) {
    struct TestCaseData *data = (struct TestCaseData *) arg;
    srand(data->seed);

    // UARF_LOG_INFO("%s -> %s,\n"
    // 	      "\tseed: %u\n"
    // 	      "\tnum_cands: %u\n"
    // 	      "\tnum_rounds: %u\n"
    // 	      "\tnum_train: %u\n"
    // 	      "\tmatch_history: %b\n"
    // 	      "\teIBRS: %d\n"
    // 	      "\tAutoIBRS: %d\n"
    // 	      "\tIBRS: %b\n"
    // 	      "\tfp_test: %b\n"
    // 	      "\tfn_test: %b\n",
    // 	      MODE_STR[data->train_mode], MODE_STR[data->signal_mode],
    // 	      data->seed, data->num_cands, data->num_rounds,
    // 	      data->num_train_rounds, data->match_history, data->eibrs,
    // 	      data->autoibrs, data->ibrs, data->fp_test, data->fn_test);

    Guest g1 = {.vcpu = NULL, .vm = NULL};
    Guest g2 = {.vcpu = NULL, .vm = NULL};
    Guest g3 = {.vcpu = NULL, .vm = NULL};

    uarf_frs_init();

    stub_main = uarf_stub_init();
    stub_gadget = uarf_stub_init();
    stub_dummy = uarf_stub_init();

    uarf_ibpb_user();

    // uarf_stibp_on_user();

    switch (data->autoibrs) {
    case MIT_SET_TURN_ON:
        uarf_autoibrs_on_user();
        break;
    case MIT_SET_TURN_OFF:
        uarf_autoibrs_off_user();
        break;
    case MIT_SET_DONT_CHANGE:
        break;
    }

    switch (data->eibrs) {
    case MIT_SET_TURN_ON:
        uarf_eibrs_on_user();
        break;
    case MIT_SET_TURN_OFF:
        uarf_eibrs_off_user();
        break;
    case MIT_SET_DONT_CHANGE:
        break;
    }

    if (data->fp_test) {
        data->num_train_rounds = 0;
    }

    // if (data->guest_interleave) {
    //     uint64_t extra_pages = 10 * (3 + 512);
    //     g3.vm = __vm_create_with_one_vcpu(&g3.vcpu, extra_pages, guest_run_return);
    // }

    for (size_t c = 0; c < data->num_cands; c++) {
        uint64_t main = uarf_rand47();
        uint64_t gadget = uarf_rand47();
        uint64_t dummy = uarf_rand47();

        printf("main: 0x%lx, gadget: 0x%lx, dummy: 0x%lx\n", main, gadget, dummy);

        // if (data->smt == SMT_MODE_TRAIN) {
        //     dummy = 0x10ab07240;
        // }

        // if (data->smt == SMT_MODE_SIGNAL) {
        //     gadget = 0x257a01000;
        // }
        uarf_jita_allocate(data->jita_main, &stub_main, main);
        uarf_jita_allocate(data->jita_gadget, &stub_gadget, gadget);
        uarf_jita_allocate(data->jita_dummy, &stub_dummy, dummy);

        if (data->smt == SMT_MODE_TRAIN) {
        }

        UarfHistory h1 = uarf_get_randomized_history();

        UarfHistory h2 = data->match_history ? h1 : uarf_get_randomized_history();

        UarfSpecData train_data = {
            .spec_prim_p = stub_main.addr,
            .spec_dst_p_p = _ul(&stub_gadget.addr),
            .fr_buf_p = UARF_FRS_BUF,
            .secret = 0,
            .hist = h1,
        };

        UarfSpecData signal_data = {
            .spec_prim_p = stub_main.addr,
            .spec_dst_p_p =
                data->fn_test ? _ul(&stub_gadget.addr) : _ul(&stub_dummy.addr),
            .fr_buf_p = UARF_FRS_BUF,
            .secret = SECRET,
            .hist = h2,
        };

        // Have to create a new vCPU as we have not proper way to unmap prior mappings
        // when using different GVAs
        if (mode_in_guest(data->train_mode) || mode_in_guest(data->signal_mode)) {
            setup_guest(&g1, mode_in_guest(data->signal_mode));
        }

        if (mode_in_guest2(data->train_mode) || mode_in_guest2(data->signal_mode)) {
            setup_guest(&g2, mode_in_guest2(data->signal_mode));
        }

        if (data->guest_interleave) {
            setup_guest(&g3, false);
        }

        switch (data->signal_mode) {
        case RUN_MODE_HOST_USER:
        case RUN_MODE_HOST_SUPERVISOR:
            UARF_LOG_INFO("Cache: %lu\n", uarf_get_access_time_cached(1000));
            UARF_LOG_INFO("Uncache: %lu\n", uarf_get_access_time_uncached(1000));
            break;
        case RUN_MODE_GUEST_USER:
        case RUN_MODE_GUEST_SUPERVISOR:
            uarf_guest_set_rip(g1.vcpu, guest_run_cache_measure);
            uarf_guest_run(g1.vcpu);
            break;
        case RUN_MODE_GUEST2_USER:
        case RUN_MODE_GUEST2_SUPERVISOR:
            uarf_guest_set_rip(g2.vcpu, guest_run_cache_measure);
            uarf_guest_run(g2.vcpu);
            break;
        case RUN_MODE_NONE:
            break;
        }

        switch (data->smt) {
        case SMT_MODE_TRAIN:
            while (true) {
                run_training(data, &train_data, &signal_data, &g1, &g2,
                             data->num_train_rounds);
                // usleep(1000);
            }
            break;
        case SMT_MODE_SIGNAL:
            while (true) {
                for (size_t i = 0; i < data->num_rounds; i++) {
                    // run_training(data, &train_data, &signal_data, &g1, &g2,
                    // data->num_rounds);
                    run_signal(data, &train_data, &signal_data, &g1, &g2);
                    // uarf_ibpb_user();
                    usleep(1000);
                }
                uint64_t *res;
                switch (data->signal_mode) {
                case RUN_MODE_HOST_USER:
                case RUN_MODE_HOST_SUPERVISOR:
                    res = _ptr(UARF_FRS_RES);
                    break;
                case RUN_MODE_GUEST_USER:
                case RUN_MODE_GUEST_SUPERVISOR:
                    res = addr_gva2hva(g1.vm, UARF_FRS_RES);
                    break;
                case RUN_MODE_GUEST2_USER:
                case RUN_MODE_GUEST2_SUPERVISOR:
                    res = addr_gva2hva(g2.vm, UARF_FRS_RES);
                    break;
                case RUN_MODE_NONE:
                    uarf_assert(false);
                    break;
                }

                if (res != _ptr(UARF_FRS_RES)) {
                    if (IN_EVALUATION_MODE) {
                        printf("%lu\t%u\n", res[SECRET], data->num_rounds);
                        uarf_frs_reset();
                    }
                    else {
                        for (size_t i = 0; i < UARF_FRS_SLOTS; i++) {
                            ((uint64_t *) UARF_FRS_RES)[i] += res[i];
                        }
                    }
                }
                uarf_frs_print();
                memset(_ptr(res), 0, UARF_FRS_RES_SIZE);
                uarf_frs_reset();
                usleep(20000);
            }
            break;
        case SMT_MODE_OFF:
            for (size_t r = 0; r < data->num_rounds; r++) {
                run_training(data, &train_data, &signal_data, &g1, &g2,
                             data->num_train_rounds);
                // usleep(1000);

                if (data->guest_interleave) {
                    UARF_LOG_DEBUG("Run interleaving vm\n");
                    guest_data.spec_data = train_data;
                    sync_global_to_guest(g3.vm, guest_data);

                    uarf_guest_set_rip(g3.vcpu, guest_run_spec_user);
                    uarf_guest_run(g3.vcpu);
                    // uarf_guest_set_rip(g3.vcpu, guest_run_return);
                    // uarf_guest_run(g3.vcpu);
                }

                run_signal(data, &train_data, &signal_data, &g1, &g2);
            }

            uint64_t *res;
            switch (data->signal_mode) {
            case RUN_MODE_HOST_USER:
            case RUN_MODE_HOST_SUPERVISOR:
                res = _ptr(UARF_FRS_RES);
                break;
            case RUN_MODE_GUEST_USER:
            case RUN_MODE_GUEST_SUPERVISOR:
                res = addr_gva2hva(g1.vm, UARF_FRS_RES);
                break;
            case RUN_MODE_GUEST2_USER:
            case RUN_MODE_GUEST2_SUPERVISOR:
                res = addr_gva2hva(g2.vm, UARF_FRS_RES);
                break;
            case RUN_MODE_NONE:
                uarf_assert(false);
                break;
            }

            if (res != _ptr(UARF_FRS_RES)) {
                if (IN_EVALUATION_MODE) {
                    printf("%lu\t%u\n", res[SECRET], data->num_rounds);
                    uarf_frs_reset();
                }
                else {
                    for (size_t i = 0; i < UARF_FRS_SLOTS; i++) {
                        ((uint64_t *) UARF_FRS_RES)[i] += res[i];
                    }
                }
            }
            break;
        }

        if (g1.vm) {
            // NOTE: Be sure to have extracted the results before if signaling was done in
            // the guest
            kvm_vm_free(g1.vm);
        }
        if (g2.vm) {
            // NOTE: Be sure to have extracted the results before if signaling was done in
            // the guest
            kvm_vm_free(g2.vm);
        }
        if (g3.vm) {
            kvm_vm_free(g3.vm);
        }

        uarf_jita_deallocate(data->jita_main, &stub_main);
        uarf_jita_deallocate(data->jita_gadget, &stub_gadget);
        uarf_jita_deallocate(data->jita_dummy, &stub_dummy);
    }

    if (!IN_EVALUATION_MODE) {
        uarf_frs_print();
    }

    // if (g3.vm) {
    //     kvm_vm_free(g3.vm);
    // }

    // Reset back to how it was (assuming it got actually changed
    // switch (data->autoibrs) {
    // case MIT_SET_TURN_ON:
    //     uarf_autoibrs_off();
    //     break;
    // case MIT_SET_TURN_OFF:
    //     uarf_autoibrs_on();
    //     break;
    // case MIT_SET_DONT_CHANGE:
    //     break;
    // }
    //
    // switch (data->eibrs) {
    // case MIT_SET_TURN_ON:
    //     uarf_eibrs_off();
    //     break;
    // case MIT_SET_TURN_OFF:
    //     uarf_eibrs_on();
    //     break;
    // case MIT_SET_DONT_CHANGE:
    //     break;
    // }

    uarf_frs_deinit();
    UARF_TEST_PASS();
}

static struct TestCaseData data[32];
static UarfJitaCtxt jita_main_call;
static UarfJitaCtxt jita_main_jmp;
static UarfJitaCtxt jita_main_ret;
static UarfJitaCtxt jita_gadget;
static UarfJitaCtxt jita_dummy;

size_t get_test_data_manual(uint32_t seed) {
    size_t data_i = 0;
    // clang-format off
	// jmp*
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_USER, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_USER, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_SUPERVISOR, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_SUPERVISOR, true, jita_main_jmp);

	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_USER, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_USER, true, jita_main_jmp);

	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_SUPERVISOR, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_SUPERVISOR, true, jita_main_jmp);

	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_USER, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_USER, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_SUPERVISOR, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_SUPERVISOR, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_USER, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_USER, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_SUPERVISOR, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_SUPERVISOR, true, jita_main_jmp);

	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_USER, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_USER, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_SUPERVISOR, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_SUPERVISOR, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_USER, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_USER, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_SUPERVISOR, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_SUPERVISOR, true, jita_main_jmp);

	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_USER, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_USER, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_SUPERVISOR, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_SUPERVISOR, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_USER, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_USER, true, jita_main_jmp);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_SUPERVISOR, false, jita_main_jmp);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_SUPERVISOR, true, jita_main_jmp);

	
	/// Call*
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_USER, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_USER, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_SUPERVISOR, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_SUPERVISOR, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_USER, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_USER, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_SUPERVISOR, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_SUPERVISOR, true, jita_main_call);

	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_USER, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_USER, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_SUPERVISOR, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_SUPERVISOR, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_USER, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_USER, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_SUPERVISOR, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_SUPERVISOR, true, jita_main_call);

	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_USER, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_USER, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_SUPERVISOR, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_SUPERVISOR, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_USER, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_USER, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_SUPERVISOR, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_SUPERVISOR, true, jita_main_call);

	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_USER, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_USER, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_SUPERVISOR, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_SUPERVISOR, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_USER, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_USER, true, jita_main_call);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_SUPERVISOR, false, jita_main_call);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_SUPERVISOR, true, jita_main_call);


	/// Ret
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_USER, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_USER, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_SUPERVISOR, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(HOST_USER, HOST_SUPERVISOR, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_USER, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_USER, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_SUPERVISOR, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(HOST_USER, GUEST_SUPERVISOR, true, jita_main_ret);

	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_USER, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_USER, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_SUPERVISOR, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, HOST_SUPERVISOR, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_USER, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_USER, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_SUPERVISOR, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(HOST_SUPERVISOR, GUEST_SUPERVISOR, true, jita_main_ret);

	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_USER, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_USER, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_SUPERVISOR, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(GUEST_USER, HOST_SUPERVISOR, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_USER, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_USER, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_SUPERVISOR, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(GUEST_USER, GUEST_SUPERVISOR, true, jita_main_ret);

	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_USER, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_USER, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_SUPERVISOR, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, HOST_SUPERVISOR, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_USER, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_USER, true, jita_main_ret);
	//
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_SUPERVISOR, false, jita_main_ret);
	// data[data_i++] = CREATE_TCD(GUEST_SUPERVISOR, GUEST_SUPERVISOR, true, jita_main_ret);
    // clang-format on

    return data_i;
}

int get_test_data_arg(uint32_t seed, int argc, char **argv) {
    UARF_LOG_TRACE("(seed: %u, argc: %d: argv: %p)\n", seed, argc, argv);
    data[0] = (struct TestCaseData) {
        .seed = seed++,
        .num_cands = 10,
        .num_rounds = 10,
        .num_train_rounds = 1,
        .train_mode = RUN_MODE_NONE,
        .signal_mode = RUN_MODE_NONE,
        .jita_main = &jita_main_call,
        .jita_gadget = &jita_gadget,
        .jita_dummy = &jita_dummy,
        .match_history = true,
        .autoibrs = MIT_SET_DONT_CHANGE,
        .eibrs = MIT_SET_DONT_CHANGE,
        .ibrs = false,
        .fp_test = false,
        .fn_test = false,
        .guest_interleave = false,
        .smt = SMT_MODE_OFF,
    };

    int opt;
    while ((opt = getopt(argc, argv, "t:s:c:r:pnjei:a:goxyh")) != -1) {
        switch (opt) {
        case 't': {
            // if (data[0].train_mode != -1) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].train_mode = get_mode_from_string(optarg);
            break;
        };
        case 's': {
            // if (data[0].signal_mode != -1) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].signal_mode = get_mode_from_string(optarg);
            break;
        };
        case 'c': {
            // if (data[0].num_cands != -1) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].num_cands = atoi(optarg);
            break;
        };
        case 'r': {
            // if (data[0].num_rounds != -1) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].num_rounds = atoi(optarg);
            break;
        };
        case 'p': {
            // if (data[0].fp_test) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].fp_test = true;
            break;
        };
        case 'n': {
            // if (data[0].fn_test) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].fn_test = true;
            break;
        };
        case 'j': {
            // if (data[0].jita_main == &jita_main_jmp) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].jita_main = &jita_main_jmp;
            break;
        };
        case 'e': {
            // if (IN_EVALUATION_MODE) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            IN_EVALUATION_MODE = true;
            break;
        };
        case 'i': {
            // if (data[0].eibrs != MIT_SET_DONT_CHANGE) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].eibrs = get_mitset_from_string(optarg);
            break;
        };
        case 'a': {
            // if (data[0].autoibrs != MIT_SET_DONT_CHANGE) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].autoibrs = get_mitset_from_string(optarg);
            break;
        };
        case 'g': {
            // if (data[0].guest_interleave) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].guest_interleave = true;
            break;
        };
        case 'o': {
            // if (data[0].ibrs) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].ibrs = true;
            break;
        };
        case 'x': {
            // if (data[0].smt != SMT_MODE_OFF) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].smt = SMT_MODE_TRAIN;
            break;
        };
        case 'y': {
            // if (data[0].smt != SMT_MODE_OFF) {
            // 	exit(ERRNO_INVALID_ARGUMENT);
            // }
            data[0].smt = SMT_MODE_SIGNAL;
            break;
        };
        case 'h': {
            printf("Usage: [OPTIONS]\n");
            printf("\n");
            printf("Options\n");
            printf("  -h                Show this help menu.\n");
            printf("  -t <DOMAIN>       Training domain (in HU, HS, GU, GS).\n");
            printf("  -s <DOMAIN>       Signaling domain (in HU, HS, GU, GS).\n");
            printf("  -c <CANDIDATES>   Number of re-randomization of addresses "
                   "(default: %u).\n",
                   data[0].num_cands);
            printf(
                "  -r <ROUNDS>       Number of repetitions per address (default: %u).\n",
                data[0].num_rounds);
            printf("  -p                IF set, measure false positive.\n");
            printf("  -n                IF set, measure false negative.\n");
            printf("  -j                IF set, use ind jmp instead of call.\n");
            printf("  -e                Evaluation mode, print results only.\n");
            printf(
                "  -i <0/1>          Disable/Enable eIBRS, otherwise leave unchanged.\n");
            printf("  -a <0/1>          Disable/Enable AutoIBRS, otherwise remains "
                   "unchanged.\n");
            printf("  -g                Run some other guest in-between training and "
                   "signaling.\n");
            printf("  -o                Enable IBRS when signaling in supervisor.\n");
            printf("  -x                Run as SMT training thread.\n");
            printf("  -y                Run as SMT signaling thread.\n");
            printf("  -h                Show this help menu.\n");
            printf("\n");
            exit(0);
            break;
        };
        }
    }

    switch (data[0].smt) {
    case SMT_MODE_TRAIN:
        data[0].seed = 123456;

        if (data[0].train_mode == -1) {
            UARF_LOG_ERROR("Argument -t is required\n");
            exit(ERRNO_INVALID_ARGUMENT);
        }

        break;
    case SMT_MODE_SIGNAL:
        data[0].seed = 123456;

        if (data[0].signal_mode == -1) {
            UARF_LOG_ERROR("Argument -s is required\n");
            exit(ERRNO_INVALID_ARGUMENT);
        }

        break;
    case SMT_MODE_OFF:

        if (data[0].train_mode == -1) {
            UARF_LOG_ERROR("Argument -t is required\n");
            exit(ERRNO_INVALID_ARGUMENT);
        }

        if (data[0].signal_mode == -1) {
            UARF_LOG_ERROR("Argument -s is required\n");
            exit(ERRNO_INVALID_ARGUMENT);
        }
        break;
    }

    return 1;
}

UARF_TEST_SUITE_ARG(argc, argv) {
    uint32_t seed = uarf_get_seed();
    size_t data_i;

    if (argc == 1) {
        UARF_LOG_DEBUG("Run manual\n");
        data_i = get_test_data_manual(seed);
    }
    else {
        UARF_LOG_DEBUG("Run arg\n");
        data_i = get_test_data_arg(seed, argc, argv);
    }

    uarf_assert(data_i < sizeof(data) / sizeof(data[0]));

    if (IN_EVALUATION_MODE) {
        uarf_log_system_base_level = UARF_LOG_LEVEL_ERROR;
    }
    else {
        uarf_log_system_base_level = UARF_LOG_LEVEL_INFO;
        uarf_log_system_level = UARF_LOG_LEVEL_INFO;
    }

    UARF_LOG_INFO("Using seed: %u\n", seed);
    uarf_pi_init();
    uarf_rap_init();

    jita_main_call = uarf_jita_init();
    jita_main_jmp = uarf_jita_init();
    jita_main_ret = uarf_jita_init();
    jita_gadget = uarf_jita_init();
    jita_dummy = uarf_jita_init();

    uarf_jita_push_psnip(&jita_main_call, &psnip_history);
    uarf_jita_push_psnip(&jita_main_call, &psnip_history);
    uarf_jita_push_psnip(&jita_main_call, &psnip_history);
    uarf_jita_push_psnip(&jita_main_call, &psnip_history);
    uarf_jita_push_psnip(&jita_main_call, &psnip_history);

    uarf_jita_clone(&jita_main_call, &jita_main_jmp);
    uarf_jita_clone(&jita_main_call, &jita_main_ret);

    uarf_jita_push_psnip(&jita_main_call, &psnip_src_call_ind);
    uarf_jita_push_psnip(&jita_main_jmp, &psnip_src_jmp_ind);
    uarf_jita_push_psnip(&jita_main_ret, &psnip_src_ret);

    uarf_jita_push_psnip(&jita_main_call, &psnip_ret);
    uarf_jita_push_psnip(&jita_main_jmp, &psnip_ret);
    uarf_jita_push_psnip(&jita_main_ret, &psnip_ret);

    uarf_jita_push_psnip(&jita_gadget, &psnip_dst_gadget);
    uarf_jita_push_psnip(&jita_dummy, &psnip_dst_dummy);

    for (size_t i = 0; i < data_i; i++) {
        UARF_TEST_RUN_CASE_ARG(basic, data + i);
    }

    uarf_pi_deinit();
    uarf_rap_deinit();

    return 0;
}
