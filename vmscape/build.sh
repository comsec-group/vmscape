#!/bin/env bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
UARF_DIR="$SCRIPT_DIR/../uARF"
ATTACK_DIR="$SCRIPT_DIR/attack"
GUEST_DIR="$SCRIPT_DIR/guest"

KERNEL_FILE="$GUEST_DIR/bzImage"
LINUX_VERSION="6.6.1"
LINUX_DIR="$GUEST_DIR/linux"
MODSYM_FILE="$LINUX_DIR/Module.symvers"
INITRD_SCRIPT="$GUEST_DIR/gen_initramfs.sh"
INITRD_MANUAL_FILE="$GUEST_DIR/initramfs-base.cpio.gz"
INITRD_EVAL_FILE="$GUEST_DIR/initramfs-eval.cpio.gz"

pushd "$GUEST_DIR"
if ! [ -d "$LINUX_DIR" ]; then
    wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.105.tar.xz
    tar -xvf linux-6.6.105.tar.xz
    mv linux-6.6.105 linux
    rm linux-6.6.105.tar.xz
    cp -v "$GUEST_DIR/linux-config" "$LINUX_DIR/.config"
fi

if ! [ -f "$KERNEL_FILE" ]; then
    echo "# Create the guest kernel image"
    make -C "$LINUX_DIR" -j "$(nproc)" bzImage
    cp -v "$LINUX_DIR/arch/x86/boot/bzImage" "$KERNEL_FILE"
fi

# build the initramfs
if ! [ -f "$INITRD_MANUAL_FILE" ]; then
    echo "# Create manual initramfs"
    bash "$INITRD_SCRIPT" --share --cwd "/mnt/" --out "$INITRD_MANUAL_FILE" --force
fi
if ! [ -f "$INITRD_EVAL_FILE" ]; then
    echo "# Create eval initramfs"
    bash "$INITRD_SCRIPT" --share --cwd "/mnt/" --out "$INITRD_EVAL_FILE" --force --init "$GUEST_DIR/init-eval.sh"
fi
rm -rf "$GUEST_DIR/initramfs"
popd

echo "# Build the kernel modules for the guest machine"
make -C "$LINUX_DIR" -j "$(nproc)" modules
make -C "$UARF_DIR" kmods KDIR="$LINUX_DIR"
cp -v "$UARF_DIR/kmods/pi/pi.ko" "$UARF_DIR/kmods/rap/rap.ko" "$ATTACK_DIR"

echo "# build the attack"
make -C "$ATTACK_DIR"
