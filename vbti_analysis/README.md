# Systematic BPU Isolation under Virtualisation

The experiment we used in section 5 of our paper to determine the BPU isolation across domain boundaries in virtualised environments.

## Reproduce
>
> [!IMPORTANT]
> We recommend to use Ubuntu 24.04, as this is the only version that we tested this on

### 1) Setup

- Run [setup.sh]()
  - Only needs to be done once per host
<details>
    <summary>Script Details</summary>
    The [setup.sh]() does:
    - Clone the Linux kernel to [./LinuxKernel]()
    - Patch its selftest infrastructure with our patches in [./selftest_patches]()
    - Install our utility library [libuarf.a]() system-wide
    - Compile the kernel with the host's config file and install it
</details>

> [!TIP]
> It is safe to run this script multiple times. But each time it will re-compile and install a new kernel.

### 2) Boot Custom Kernel

- Boot into the freshly installed kernel
  - Our script does not configure your bootloader to do this. You need to do this manually
  - The kernel contains the identifier `vmscape`
- The kernel already contains the patches for VMScape. Use the kernel argument `vmscape=off` to disable it. Otherwise, you essentially verify the working of the mitigation

### 3) Run the Experiment

- Run [prepare.sh]()
  - Needs to be done after each system restart
<details>
    <summary>Script Details</summary>
    The [prepare.sh]() does:
    - Loads the required kernel modules
    - Clone the Linux kernel to [./LinuxKernel]()
    - Patch its selftest infrastructure with our patches in [./selftest_patches]()
    - Install our utility library [libuarf.a]() system-wide
    - Compile the kernel with the host's config file and install it
</details>

- Navigate to the selftest directory [./LinuxKernel/tools/testing/selftest/kvm]()
- Compile the selftests: `make`
- Verify selftest setup: `./x86/exa_guest`
<details>
    <summary>Expected Output</summary>
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
</details>

- Run the experiemnt: `./x86/exp_guest_bti FLAGS`

###### Details
- See `-h` for the help menu
- You always need to specify the training domain `-t DOM` and signaling domain `-s DOM`
    - `DOM` is one of HU, HS, GU, GS
- The cache threshold needs to be adjusted for each host system and potentially also signaling domain
    - An initial cache measurement done for each run indicates whether the current set value is appropriate
    - Adjust `#define UARF_FRS_THRESH` in the experiment accordingly
    - (Optional) Use the false-positive flag `-p` and false-negative flag `-n` to verify the current value
        - With `-p` all entries should be zero
        - With `-n` entry `SECRET=8` should be $100$ (unless changed via other flags), all others zero

### 4) Teardown and Cleanup

- Boot back into the default kernel
- Run [cleanup.sh]()

<details>
    <summary>Script Details</summary>
    The [cleanup.sh]() script does:
    - Uninstall all custom kernels installed by the [setup.sh]() script
    - Uninstall [libuarf.a]()
</details>
