/**
 * Hello World program running code in a kvm VM
 *
 * This file is a kvm selftest.
 * Designed to work with Linux v6.6
 *
 * Steps to run:
 * - Open `tools/testing/selftests/kvm/`
 * - Copy this test to `kvm/x86_64/rev_eng`
 * - Symlink uARF root into `kvm/lib` as `uarf`
 * - Symlink uARF/include into `kvm/include` as `uarf`
 * - Edit `kvm/Makefile`
 *    - Add `TEST_GEN_PROGS_x86_64 += x86_64/rev_eng/exa_guest`
 *    - Add `LDLIBS += -L./lib/uarf -luarf`
 * - Run `make && ./x86_64/rev_eng/ex_guest`
 */

#include "processor.h"

#include <err.h>
#include <syscall.h>
#include <unistd.h>

#include <asm/processor-flags.h>
#include <kvm_util.h>
#include <ucall_common.h>

#include "uarf/guest.h"
#include "uarf/jita.h"
#include "uarf/kmod/pi.h"
#include "uarf/kmod/rap.h"
#include "uarf/lib.h"
#include "uarf/psnip.h"
#include "uarf/test.h"

#define uarf_guest_set_rip(vcpu, target)                                                 \
    ({                                                                                   \
        struct kvm_regs regs;                                                            \
        vcpu_regs_get(vcpu, &regs);                                                      \
        regs.rip = (unsigned long) target;                                               \
        vcpu_regs_set(vcpu, &regs);                                                      \
    })

#define NUM_ADDITINAL_PAGES 1

uarf_psnip_declare_define(test_dst, "lfence\n"
                                    "ret\n"
                                    "int3\n");

typedef struct registers {
    union {
        void *code_ptr;
        uint64_t code_addr;
        void (*f)(void *);
    };
} registers_t;

registers_t registers;

void do_call(registers_t *r) {
    asm volatile("call *%0\n" ::"r"(r->code_ptr) :);
}

static void guest_main(void) {
    uarf_init_syscall(uarf_syscall_handler_return, KERNEL_CS, USER_CS_STAR);

    GUEST_PRINTF("Hello from Guest Supervisor!\n");
    GUEST_PRINTF("Running in ring %u\n", uarf_get_ring());
    do_call(&registers);

    uarf_supervisor2user(USER_DS, USER_CS);
    GUEST_PRINTF("Dropped privileges to user\n");
    GUEST_PRINTF("Running in ring %u\n", uarf_get_ring());
    do_call(&registers);

    uarf_user2supervisor();
    GUEST_PRINTF("Escalated privileges to supervisor\n");
    GUEST_PRINTF("Running in ring %u\n", uarf_get_ring());
    do_call(&registers);

    uarf_supervisor2user(USER_DS, USER_CS);
    GUEST_PRINTF("Dropped privileges to user\n");
    GUEST_PRINTF("Running in ring %u\n", uarf_get_ring());
    do_call(&registers);

    uarf_user2supervisor();
    GUEST_PRINTF("Escalated privileges to supervisor\n");
    GUEST_PRINTF("Running in ring %u\n", uarf_get_ring());
    do_call(&registers);

    GUEST_PRINTF("Exiting VM\n");
    GUEST_DONE();
    return;
}

static void run_vcpu(struct kvm_vcpu *vcpu) {
    struct ucall uc;

    while (true) {
        vcpu_run(vcpu);

        switch (get_ucall(vcpu, &uc)) {
        case UCALL_SYNC:
            printf("Got sync signal\n");
            printf("With %lu arguments\n", uc.args[1]);
            break;
        case UCALL_DONE:
            printf("Got done signal\n");
            return;
        case UCALL_ABORT:
            printf("Got abort signal\n");
            REPORT_GUEST_ASSERT(uc);
            break;
        case UCALL_PRINTF:
            printf("guest | %s", uc.buffer);
            break;
        case UCALL_NONE:
            printf("Received none, of type: ");
            switch (vcpu->run->exit_reason) {
            case KVM_EXIT_SHUTDOWN:
                printf("Shutdown\n");
                printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
                printf("Most likely something went wrong. VM quit\n");
                printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
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

void copy_to_guest(struct kvm_vm *vm, UarfStub *stub) {
    static u64 next_slot = NR_MEM_REGIONS;
    static u64 used_pages = 0;

    u64 guest_num_pages = stub->size / PAGE_SIZE;
    u64 guest_test_phys_mem = (vm->max_gfn - used_pages - guest_num_pages) * PAGE_SIZE;

    // map guest memory
    vm_userspace_mem_region_add(vm, DEFAULT_VM_MEM_SRC, guest_test_phys_mem, next_slot,
                                guest_num_pages, 0);
    virt_map(vm, stub->base_addr, guest_test_phys_mem, guest_num_pages);
    used_pages += guest_num_pages;
    ++next_slot;

    // copy the data to the guest
    u64 *addr = addr_gpa2hva(vm, (vm_paddr_t) guest_test_phys_mem);
    memcpy(addr, stub->base_ptr, stub->size);
}

int test(void) {
    // prepare VM
    struct kvm_vcpu *vcpu;
    struct kvm_vm *vm;

    printf("Create VM\n");
    // VM wants to know total extra memory for page tables
    // * 4 * 512 is needed cause the utils assume consecutive memory pages
    u64 extra_pages = NUM_ADDITINAL_PAGES * 2 * (2 * 512);
    vm = __vm_create_with_one_vcpu(&vcpu, extra_pages, guest_main);


    // vm_init_descriptor_tables(vm);
    // vcpu_init_descriptor_tables(vcpu);

    // vcpu_init_descriptor_tables(vcpu);
    // vm_install_exception_handler(vm, <NR>, <HANDLER>); // Register handler if required

    // allocate some code
    UarfJitaCtxt jita = uarf_jita_init();
    uarf_jita_push_psnip(&jita, &test_dst);
    UarfStub stub = uarf_stub_init();
    u64 train_dst_addr = uarf_rand47();
    uarf_jita_allocate(&jita, &stub, train_dst_addr);

    // also map the code into the VM
    copy_to_guest(vm, &stub);

    printf("send state information to VM\n");
    // inform the guest about the current configuration
    registers.code_addr = train_dst_addr;
    sync_global_to_guest(vm, registers);

    // Host user
    printf("run in host user\n");
    do_call(&registers);
    uarf_rup_call(registers.code_ptr, NULL);

    // Host kernel
    printf("run in host kernel\n");
    uarf_rap_call(registers.code_ptr, NULL);

    // Guest supervisor and user
    printf("run in guest supervisor and user\n");
    run_vcpu(vcpu);

    // Run the VM again by changing the IP
    printf("Run guest again\n");
    uarf_guest_set_rip(vcpu, guest_main);
    run_vcpu(vcpu);

    // cleanup
    uarf_jita_deallocate(&jita, &stub);
    kvm_vm_free(vm);

    return 0;
}

UARF_TEST_SUITE() {
    uint32_t seed = uarf_get_seed();
    UARF_LOG_INFO("Using seed: %u\n", seed);

    srandom(getpid());

    uarf_rap_init();
    uarf_pi_init();

    test();

    uarf_rap_deinit();
    uarf_pi_init();

    printf("done\n");
}
