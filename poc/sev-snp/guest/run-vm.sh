#!/bin/env bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
cd "$SCRIPT_DIR"

make -C "$SCRIPT_DIR/../"

sudo virt-copy-in -a "$SCRIPT_DIR/debian-12-nocloud-amd64.qcow2" "$SCRIPT_DIR/../amd_sev_snp" /root/

QEMU_BIN="$SCRIPT_DIR/qemu-sevsnp/usr/local/bin/qemu-system-x86_64"
sudo taskset -c 3 "$QEMU_BIN" \
    -m 5G \
    -cpu EPYC-v4 \
    -machine q35 \
    -enable-kvm \
    -device rocker \
    -drive "if=virtio,format=qcow2,file=$SCRIPT_DIR/debian-12-nocloud-amd64.qcow2" \
    -nographic \
    -bios "$SCRIPT_DIR/OVMF_SNP.fd" \
    -machine memory-encryption=sev0,vmport=off \
    -object memory-backend-memfd,id=ram1,size=5G,share=true,prealloc=false \
    -machine memory-backend=ram1 \
    -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1,kernel-hashes=off
