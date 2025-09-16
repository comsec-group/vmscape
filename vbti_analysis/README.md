# Systematic BPU Isolation under Virtualisation

The experiment we used in section 5 of our paper to determine the BPU isolation across domain boundaries in virtualised environments.

## Reproduce

> [!IMPORTANT]
> We recommend to use Ubuntu 24.04, as this is the only version that we tested this on

### 1) Setup

- Run [setup.sh]()
  - Only needs to be done once per host
  - Script Details
    - Install dependencies
    - Clone the Linux kernel to [./LinuxKernel]()
    - Patch its selftest infrastructure with our patches in [./selftest_patches]()
    - Install our utility library [libuarf.a](../uARF) system-wide
    - Compile the kernel with the host's config file and install it

> [!TIP]
> It is safe to run this script multiple times. But each time it will re-compile and install a new kernel.

### 2) Boot Custom Kernel

- Boot into the freshly installed kernel
  - Our script does not configure your bootloader to do this. You need to do this manually
  - The kernel contains the identifier `vmscape`
- The kernel already contains the patches for VMScape. Use the kernel argument `vmscape=off` to disable it. Otherwise, you essentially verify the working of the mitigation
- Additionally, also disable SMEP and SMAP via the kernel arguments: `nosmap nosmep clearcpuid=295,308`
    - Our experiments disables them dynamically. However, we have found that this works unreliably.

### 3) Run the Experiment

- Run [prepare.sh]()
  - Needs to be done after each system restart
  - Script Details
    - Loads the required kernel modules

- Navigate to the selftest directory [./LinuxKernel/tools/testing/selftest/kvm]()
- Compile the selftests: `make`
- Verify selftest setup: `./x86/exa_guest`
  - Expected Output

    ```
    host@node:~/Artifacts/analysis/LinuxKernel/tools/testing/selftests/kvm$ ./x86/exa_guest
    Random seed: 0x6b8b4567
    [INFO] x86/exa_guest.c:217:main Using seed: 2245951179
    Create VM
    send state information to VM
    run in host user
    run in host kernel
    run in guest supervisor and user
    guest | Hello from Guest Supervisor!
    guest | Running in ring 0
    guest | Dropped privileges to user
    guest | Running in ring 3
    guest | Escalated privileges to supervisor
    guest | Running in ring 0
    guest | Dropped privileges to user
    guest | Running in ring 3
    guest | Escalated privileges to supervisor
    guest | Running in ring 0
    guest | Exiting VM
    Got done signal
    Run guest again
    guest | Hello from Guest Supervisor!
    guest | Running in ring 0
    guest | Dropped privileges to user
    guest | Running in ring 3
    guest | Escalated privileges to supervisor
    guest | Running in ring 0
    guest | Dropped privileges to user
    guest | Running in ring 3
    guest | Escalated privileges to supervisor
    guest | Running in ring 0
    guest | Exiting VM
    Got done signal
    done
    ```

- Run the experiemnt: `./x86/exp_guest_bti FLAGS`

#### Details

- See `-h` for the help menu
- By default you should get hits in the column `SECRET=5`

- **Cache Threshold**
  - The cache threshold needs to be adjusted for each host system and potentially also signaling domain
    - During each experiment run the cache timings are measured and reported
    - Adjust `#define UARF_FRS_THRESH` in the [experiment](./selftests/exp_guest_bti.c) if required and re-compile the experiment
    - (Optional) Use the false-positive flag `-p` and false-negative flag `-n` to verify the current value
      - With `-p` all entries should be zero
      - With `-n` entry `SECRET=8` should be $100$ (unless changed via other flags), all others zero
      - Obviously, the results are rarely perfect due to noise

- **BTB Isolation**
  - You always need to specify the training domain `-t DOM_1` and signaling domain `-s DOM_2`
    - `DOM` is one of HU, HS, GU, GS

- **SMT Isolation**
    - Run the signaler and keep it running: `taskset -c <SOME_CORE> ./x86/exp_guest_bti -s DOM_1 -y`
    - Run the trainer: `taskset -c <SOMES_SMT_CORE> ./x86/exp_guest_bti -t DOM -x`
        - Repeatedly run and stop the trainer to see its effect on the signaler

### 4) Teardown and Cleanup

- Boot back into the default kernel
- Run [cleanup.sh]()
  - Script Details
    - Uninstall all custom kernels installed by the [setup.sh]() script
    - Uninstall [libuarf.a](../uARF)


## Troubleshooting

- **Bad file descriptor:** You see the following or similar output
    ```
    Failed to rap
    : Bad file descriptor
    ```
    - Run [./prepare.sh]()

- **Experiment gets `killed`**
    - Ensure you boot the kernel with SMEP and SMAP disabled

- **No Signal**
     - Ensure you have correctly configured the cache threshold
     - Ensure you boot the kernel with VMScape mitigation disabled
