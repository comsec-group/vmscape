#!/bin/env bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
GUEST_DIR="$SCRIPT_DIR"
UARF_DIR="$SCRIPT_DIR/../../../uARF"
DEBIAN_IMG="$GUEST_DIR/debian-12-nocloud-amd64.qcow2"
QEMU_BIN="$SCRIPT_DIR/qemu-sevsnp/usr/local/bin/qemu-system-x86_64"

setup=false

# build the test code
make -C "$SCRIPT_DIR/../"

# prepare the guest image
if ! [ -f "$DEBIAN_IMG" ]; then
    wget -O "$DEBIAN_IMG" https://cloud.debian.org/images/cloud/bookworm/20250909-2230/debian-12-nocloud-amd64-20250909-2230.qcow2
    setup=true
fi
# copy the tools into the VM
sudo virt-copy-in -a "$DEBIAN_IMG" "$SCRIPT_DIR/../amd_sev_snp" /root/

if "$setup"; then
    # install packages on first boot
    sudo virt-copy-in -a "$DEBIAN_IMG" "$UARF_DIR" /root
    sudo virt-customize -a "$DEBIAN_IMG" --firstboot-install linux-headers-amd64,build-essential --firstboot-command 'make -C "/root/uARF" kmods; cp -v /root/uARF/kmods/pi/pi.ko /lib/modules/$(uname -r)/kernel/; depmod; shutdown now'
    sudo virt-copy-in -a "$DEBIAN_IMG" "$SCRIPT_DIR/vBTI-modules.conf" /etc/modules-load.d/

    # boot once to perform setup
    sudo qemu-system-x86_64 \
        -m 5G \
        -cpu EPYC-v4 \
        -machine q35 \
        -enable-kvm \
        -drive "if=virtio,format=qcow2,file=$SCRIPT_DIR/debian-12-nocloud-amd64.qcow2" \
        -nographic \
        -bios "$SCRIPT_DIR/OVMF_SNP.fd"
fi

# we need ASLR disabled for this test
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

sudo taskset -c 3 "$QEMU_BIN" \
    -m 5G \
    -cpu EPYC-v4 \
    -machine q35 \
    -enable-kvm \
    -drive "if=virtio,format=qcow2,file=$SCRIPT_DIR/debian-12-nocloud-amd64.qcow2" \
    -nographic \
    -bios "$SCRIPT_DIR/OVMF_SNP.fd" \
    -machine memory-encryption=sev0,vmport=off \
    -object memory-backend-memfd,id=ram1,size=5G,share=true,prealloc=false \
    -machine memory-backend=ram1 \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=off
