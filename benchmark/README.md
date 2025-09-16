# Benchmark Mitigations

Benchmarks we used in §9.2 of our paper to evaluate the performance of the mitigations.

## Reproduce

> [!IMPORTANT]
> We recommend to use Ubuntu 24.04, as this is the only version that we tested this on

### 1) Setup
- Unless noted otherwise, run all commands local to this directory
- Install dependencies: `libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf dwarves libdw-dev debhelper-compat qemu qemu-kvm debootstrap`
- Run [./gen_debian_drive.sh -s]()
    - Only needs to be done once per host
    - Script details
        - Generates Debian-based guest drive
- Build and install custom `vmscape` kernel as described in [vbti_analysis](../vbti_analysis)
- Build guest kernel `bzImage`
    - Use the kernel tree in [../vbti_analysis/LinuxKernel](), once the [../vbti_analysis/setup.sh]() was run
    - Configure kernel with `make x86_64_defconfig` followed by `make kvm_guest.config`
    - Build kernel `make -j "$(nproc)"`
    - Copy `arch/x86/boot/bzImage` to CWD

### 2.a) Run UnixBench Benchmark
The general procedure to run UnixBench in the guest
- Launch VM: `./run_qemu_unixbench.sh`
- In the guest, navigate to `/mnt/host0/byte-unixbench/Unixbench` and run the benchmark: `./Run`

### 2.b) Run fio Benchmark
The general procedure to run fio in the guest
- Launch VM: `./run_qemu_fio.sh`
- In the guest, navigate to `/mnt/host0/` and run the benchmark: `./run_fio.sh`

#### Benchmark the VMScape patch
- Get baseline measure:
    - Boot `vmscape` kernel with `vmscape=off`
    - Run benchmark
- Get mitigation measure:
    - Boot `vmscape` kernel without changing `vmscape`
    - Run benchmark

#### Benchmark IBPB-on-VMExit
- Get baseline measure:
    - Boot `vmscape` kernel with `vmscape=off`
    - Run benchmark
- Get mitigation measure:
    - Apply patch [./0001-Execute-IBPB-on-every-VMExit.patch]() to ref `223ba8ee0a3986718c874b66ed24e7f87f6b8124`, compile and install kernel
    - Boot new custom kernel with `vmscape=off`
    - Run benchmark

#### Benchmark Retpoline
- Compile custom QEMU with `./build_qemu.sh` and `./build_qemu.sh -r`
    - ELFs are symlinked to `qemu-system-x86_64` and `qemu-system-x86_64_retpoline`
- Get baseline measure:
    - Boot `vmscape` kernel with `vmscape=off`
    - Run benchmark using `QEMU_ELF=./qemu-system-x86_64 ./run_qemu_xxx.sh`
- Get mitigation measure:
    - Boot new custom kernel with `vmscape=off`
    - Run benchmark using `QEMU_ELF=./qemu-system-x86_64_retpoline ./run_qemu_xxx.sh`

### 3) Evaluate
- For unixbench, use `./evaluate_unixbench.py <BASELINE_FILE> <MITIGATION_FILE>`
- For fio, use `./evaluate_fio.py <BASELINE_FILE> <MITIGATION_FILE>`
