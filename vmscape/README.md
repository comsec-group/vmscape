# VMScape

Our end-to-end exploit leaking QEMU secrets on Zen 4.
These microarchitectural attacks require fine-tuning for the specific processors they are running on.
The attack has two configurations: one for the AMD Ryzen 7 7700X Zen 4 processor and another for the AMD EPYC 9555 Zen 5 processor.
We recommend to run the experiment on an Ubuntu 24.04 and use our systemd-nspawn container to run the correct qemu binaries.

**Dependencies**

wget cpio build-essential libncurses-dev bison bc flex libssl-dev libelf-dev

**Run**
```bash
# build the components
bash build.sh

# for zen 5, additionally run this
# make -C attack clean
# make -C attack MARCH=MARCH_ZEN5

# enter the reproducible ubuntu 25.10 container to use the correct qemu binary
bash container.sh

# run the virtual machine
bash guest/run-vm.sh

# inside the virtual machine that just started you can run the attack
./attack

# to stop the virtual machine, press Ctrl-A, X
```
