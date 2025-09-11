# μ-Architecture Reverse Engineering Framework (uARF)

uARF is a framework that facilitates and supports the reverse engineering and understanding of the micro-architecture of modern CPUs (x86-64).

### Feature Overview
- Just-in-Time Assembler (JITA): Dynamically generates object code at runtime.
- Seamless Assembly Code Integration: Easily embed assembly (ASM) into experiments.
- Fine-grained Code Placement: Control exactly where object code is placed in memory.
- Privilege Escalation Mechanisms: Run privileged instructions from user mode via a kernel module.
- Supervisor Mode Execution: Execute arbitrary code in supervisor mode via a kernel module.
- Flush-and-Reload Side Channel: Utilize a well-known side-channel attack technique.
- Performance Counter Interaction: Precisely measure code sections with performance counters.
- KVM Selftest Integration: Run arbitrary code in guest supervisor/user mode.
- Speculative Execution Experiments: Includes helper functions and snippets for writing Spetre experiments.
- Logging & Synchronization: Built-in logging and remote synchronization mechanisms.

## Getting Started
uARF can be used in two ways:
    1. Integrate your experiments into the framework’s build system.
    2. Build and include uARF as a library in your project.

### Integrate Tests
- Implement your experiment inside `./tests`, e.g. `./tests/test_helloworld.c`
    - See `./tests/exa_*` for examples.
    - See `./tests/exp_*` for real experiments.
    - See `./tests/test_*` for unittests.
- If desired, create `./tests/test_helloworld_asm.S` alongside test file
    - Important to follow this pattern, otherwise the ASM is integrated into your experiment
- Adapt `TESTCASE` in `.config` to point to your experiments
    - E.g. `TESTCASE=test_helloworld`
- Build by running `make test`
- Execute binary `./test_helloworld.bin`

### Build as Library
- Build library `make libuarf.a`
- Integrate `./libuarf.a` into your own project
- Include `./include` in your project

## Kernel Modules
uARF comes with three kernel modules:
- Privileged Instruction (pi): Run a privileged instruction as a user
- Run as Privileged (rap): Run arbitrary code as supervisor
- Dump cr3 (cr3): Reading `/proc/uarf_cr3` returns the cr3 of all processes

### How to
- Need to be compiled for the target's kernel version
- Select target by setting `PLATFORM=<TARGET>` in `.config`
- `<TARGET>` corresponds to file `config/<TARGET>.config`
    - Contains `KDIR=<PATH_TO_KERNEL>`
- Build modules `make kmods`
- (Re-)Load modules manually or using `./scripts/kmod.sh <MODULE_NAME>`

## KVM Selftest Integration
The Linux Kernel provides a selftest environment that allow to run KVM based guests. By default, those guests run in supervisor mode. Using uARF you can also run arbitrary code as guest user. See `./tests/exa_guest.c` for hello-world on how to run the same code as *host user*, *host supervisor*, *guest user* and *guest supervisor*.

### How to
- Build uARF as a shared library
- All subsequent commands are run within the Linux Kernel Source
- uARF is designed to work with Linux Kernel v6.6.
    - Run `git checkout v6.6`
- Apply patch `./linux/patches/0001-Integrate-uARF-framework-and-adjust-for-ASM-support.patch`
    - Check stats `git apply --stat <0001_PATCH>`
    - Dry run `git apply --check <0001_PATCH>`
    - Apply `git am < <0001_PATCH>`
- Fix uARF include and library paths
    - `tools/testing/selftests/kvm/include/uarf` must point to `<UARF_ROOT>/include`
    - `tools/testing/selftests/kvm/lib/uarf` must point to `<UARF_ROOT>`
- Apply patch `./linux/patches/0002-Add-support-for-guest-user.patch`
- Write experiments inside `tools/testing/selftests/kvm/x86_64/rev_eng`, similarly as when writing them in uARF
    - You can again have an attendant ASM file
- Make your experiment known to the build system by adding `TEST_GEN_PROGS_x86_64 += x86_64/rev_eng/<EXPERIMENT_BASE_NAME>` to `tools/testing/selftests/kvm/Makefile`
- Also add `TEST_GEN_FILES += x86_64/rev_eng/<EXPERIMENT_BASE_NAME>_asm.o` if your experiment has an attendant ASM file
- Build the experiment `make -C tools/testing/selftests/kvm`
- Run the experiment `./tools/testing/selftests/kvm/x86_64/rev_eng/<EXPERIMENT_BASE_NAME>`

## Syncer
Automatically sync this framework, and/or your experiments to a remote. Synchronisation is based on configuration files.

### How to
- Define a configuration file, e.g. in `./misc/<TARGET_CONFIG>`
    - See `./scripts/sync.sh --help` for information on the structure of the config
    - Config is interpreted as a bash file, so you can compute these file lists
- Run syncer `./scripts/sync.sh <PATH_TO_TARGET_CONFIG>`
    - Run with `--daemon` to keep syncing changes in the background
    - See `./scripts/sync.sh --help` for more information on options and flags

