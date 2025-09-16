# SEV-SNP Test

This experiment performs a simple test of whether a branch on the host is used to predict a branch in an SEV-SNP guest.
The experiment only checks one simple case which means a positive indicates a problem whereas a negative does **not** guarantee proper isolation.

We use a custom compiled qemu since the default on Ubuntu 24.04 did not support sev-snp at the time.
We compiled the binary from git commit `2af4a82ab2cce3412ffc92cd4c96bd870e33bc8e` and have included it in this repo ([qemu](./guest/qemu-sevsnp/)) for convenience and because the experiment has hardcoded the branch source and target locations.

# Dependencies

wget, build-essential, qemu-system-x86_64, guestfs-tools

# Run

```bash
# Setup and run the SEV-SNP virtual machine:
bash guest/run-vm.sh

# type root and Enter to login to the VM
root

# Run the PoC
./amd_sev_snp
```