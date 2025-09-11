# Patches

This directory contains a set of patches that allow for running experiments withing the Linux Kernel selftest environment.

All patches are based of kernel version v6.6.

## Description

### 0001-Integrate-uARF-framework-and-adjust-for-ASM-support.patch
General setup that integrates uARF into the selftest build system. To minimize changes to the Makefile, while maintaining flexibility in the compilation of uARF, the framework is integrated as a static library.
The patch creates two symlinks within the kernel tree to the uARF source. Those are `tools/testing/selftest/kvm/lib/uarf` and `tools/testing/selftest/kvm/include/uarf`. They need to be adjusted accordingly to point to the uarf root and `uarf/include`, respectively.

### 0002-Add-support-for-guest-user.patch
Adds support for a guest user. The patch itself does not provide the functionality for doing the switches. Those are provided as part of uARF
