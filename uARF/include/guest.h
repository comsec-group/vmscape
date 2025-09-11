/*
 * Helper for running code in the guest using kvm.
 */

#pragma once

#include "compiler.h"
#include "lib.h"

/**
 * Get the current ring from CS
 */
static __always_inline uint8_t uarf_get_ring(void) {
    uint64_t cs;
    asm volatile("movq %%cs, %0\n\t" : "=r"(cs));
    return cs & 3;
}

/**
 * Drop privileges from supervisor to user using iret
 */
#define UARF_X86_EFLAGS_IF_BIT   9 /* Interrupt Flag */
#define UARF_X86_EFLAGS_IF       BIT_T(uint64_t, UARF_X86_EFLAGS_IF_BIT)
#define UARF_X86_EFLAGS_IOPL_BIT 12 /* I/O Privilege Level (2 bits) */
#define UARF_X86_EFLAGS_IOPL     (3ul << UARF_X86_EFLAGS_IOPL_BIT)
static __always_inline void uarf_supervisor2user(uint64_t user_ds, uint64_t user_cs) {
    asm volatile(
        /* Disable interrupts */
        "cli\n\t"

        "movq %%rsp, %%rax\n\t"

        /* Push User SS */
        "pushq %[user_ds]\n\t"

        /* Push RSP */
        "pushq %%rax\n\t"

        /* Push RFLAGS and re-enable interrupts */
        "pushfq\n\t"

        "orq %[rflag_op], (%%rsp)\n\t"

        /* Push User CS */
        "pushq %[user_cs]\n\t"

        /* Push User RIP */
        "lea return_here%=, %%rax\n\t"
        "pushq %%rax\n\t"

        /* Pray */
        "iretq\n\t"

        "return_here%=:\n\t"
        /* TODO clobber stuff */
        ::[user_ds] "i"(user_ds),
        [user_cs] "i"(user_cs), [rflag_op] "r"(UARF_X86_EFLAGS_IOPL | UARF_X86_EFLAGS_IF)
        : "rax", "memory");
}

/**
 * Escalate privileges from user to supervisor using syscall
 */
static __always_inline void uarf_user2supervisor(void) {
    asm volatile("mov $1, %%rax\n\t" // Set syscall number
                 "syscall\n\t" ::
                     : "rax", "rcx", "r11");
}

/**
 * Set `handler` as our syscall handler.
 */
static inline void uarf_init_syscall(void (*handler)(void), uint16_t kernel_cs,
                                     uint16_t user_cs_star) {
    // Enable syscalls
    uarf_wrmsr(MSR_EFER, uarf_rdmsr(MSR_EFER) | MSR_EFER__SCE);

    // Set handler
    uarf_wrmsr(MSR_LSTAR, _ul(handler));

    // Set segments
    uarf_wrmsr(MSR_STAR, _ul(kernel_cs) << 32 | _ul(user_cs_star) << 48);
}

/**
 * A syscall handler, that simply returns to the syscall callsite
 *
 * As it uses return instead of sysret, it essentially allows to escalate privileges.
 *
 * Must be static and not inlined, other we cannot access it from guest.
 */
static void __attribute__((used)) uarf_syscall_handler_return(void) {
    asm volatile("pushq %%rcx\n\t" ::: "memory");
    return;
}

#define uarf_guest_set_rip(vcpu, target)                                                 \
    ({                                                                                   \
        struct kvm_regs regs;                                                            \
        vcpu_regs_get(vcpu, &regs);                                                      \
        regs.rip = (unsigned long) target;                                               \
        vcpu_regs_set(vcpu, &regs);                                                      \
    })

// static void uarf_guest_run(struct kvm_vcpu *vcpu)
// {
// 	struct ucall uc;
//
// 	while (true) {
// 		vcpu_run(vcpu);
//
// 		switch (get_ucall(vcpu, &uc)) {
// 		case UCALL_SYNC:
// 			printf("Got sync signal\n");
// 			printf("With %lu arguments\n", uc.args[1]);
// 			break;
// 		case UCALL_DONE:
// 			printf("Got done signal\n");
// 			return;
// 		case UCALL_ABORT:
// 			printf("Got abort signal\n");
// 			REPORT_GUEST_ASSERT(uc);
// 			break;
// 		case UCALL_PRINTF:
// 			printf("guest | %s", uc.buffer);
// 			break;
// 		case UCALL_NONE:
// 			printf("Received none, of type: ");
// 			switch (vcpu->run->exit_reason) {
// 			case KVM_EXIT_SHUTDOWN:
// 				printf("Shutdown\n");
// 				printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
// 				printf("Most likely something went wrong. VM quit\n");
// 				printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
// 				return;
// 			default:
// 				printf("%s\nContinue\n",
// 				       exit_reason_str(vcpu->run->exit_reason));
// 				break;
// 			}
// 			break;
// 		default:
// 			TEST_ASSERT(false, "Unexpected exit: %s",
// 				    exit_reason_str(vcpu->run->exit_reason));
// 		}
// 	}
// }
