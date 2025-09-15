# VMScape

Our end-to-end exploit leaking QEMU secrets on Zen 4.
These microarchitectural attacks require fine-tuning for the specific processors they are running on.
The attack currently present in this directory was tuned specifically for the Ryzen 7 7700X Zen 4 processor.
Since Ubuntu 25.10 is not yet stable, you might experience some issues when building.
We recommend to instead prepare the server with Ubuntu 24.04 and use our systemd-nspawn container to run the correct binaries.

**Dependencies**

wget cpio build-essential libncurses-dev bison bc flex libssl-dev libelf-dev

**Run**
```bash
# build the components
bash build.sh

# enter the reproducible ubuntu 25.10 container to use the correct qemu binary
bash container.sh

# run the virtual machine
bash guest/run-vm.sh

# inside the virtual machine that just started you can run the attack
./attack
```

> [!todo] More details will be added in the coming days

