#!/bin/env bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
UARF_DIR="$SCRIPT_DIR/../../uARF"
ATTACK_DIR="$SCRIPT_DIR/../attack"

KERNEL_FILE="$SCRIPT_DIR/bzImage"
LINUX_VERSION="6.6.1"
LINUX_DIR="$SCRIPT_DIR/linux"
MODSYM_FILE="$LINUX_DIR/Module.symvers"
INITRD_SCRIPT="$SCRIPT_DIR/gen_initramfs.sh"
INITRD_MANUAL_FILE="$SCRIPT_DIR/initramfs-base.cpio.gz"
INITRD_EVAL_FILE="$SCRIPT_DIR/initramfs-eval.cpio.gz"
SECRET_FILE="$SCRIPT_DIR/secret.txt"
DEFAULT_SECRET_SIZE=4096

QCOW_SECRET_NAME="disk_key"
QCOW_FILE="$SCRIPT_DIR/enc.qcow2"
export QEMU_MODULE_DIR

# default args
eval=false
initrd_file="$INITRD_MANUAL_FILE"
secret_size="$DEFAULT_SECRET_SIZE"

function usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "   -e, --eval             Run VM in evaluation mode."
    echo "   -h, --help             Display this help message."
}

function random_string() {
    min="$1"
    max="$2"
    count="$((RANDOM % (max - min + 1) + min))" 
    # random string of random length makes sure that the secret is not always in the same place
    tr -dc A-Za-z0-9 2>/dev/null </dev/urandom | head -c "$count"
}

PARSED_ARGUMENTS=$(getopt --name "$0" --options=h --longoptions demo,eval,help -- "$@")
VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" != "0" ]; then
    echo "Invalid argument"
    usage
    exit 1
fi

eval set -- "$PARSED_ARGUMENTS"
while [ "$#" -gt 1 ]; do
    case "$1" in
        --demo)
            secret_size=32
            demo=true
            shift
            ;;
        --eval)
            secret_size=4096
            initrd_file="$INITRD_EVAL_FILE"
            eval=true
            set -x # for better visibility of the executed commands in eval mode
            shift
            ;;
        -h|--help)
            usage
            exit 1
            ;;
        *)
            # We check for invalid options before. So this should not happen
            echo "Should not be executed ($0)"
            exit 2
            ;;
    esac
done

if ! [ -f "$KERNEL_FILE" ]; then
    echo "# Create the guest kernel image"
    if ! [ -d "$LINUX_DIR" ]; then
        pushd "$SCRIPT_DIR"
        # git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git --branch v6.6 --single-branch --depth 1 "$LINUX_DIR"
        wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.105.tar.xz
        tar -xvf linux-6.6.105.tar.xz
        mv linux-6.6.105 linux
        rm linux-6.6.105.tar.xz
        # patch because the linux kernel cannot handle Ubuntu 25.10 yet.
        patch "$LINUX_DIR/Makefile" "$SCRIPT_DIR/linux.patch"
        popd
    fi
    cp -v "$SCRIPT_DIR/linux-config" "$LINUX_DIR/.config"
    make -C "$LINUX_DIR" -j "$(nproc)" bzImage
    cp -v "$LINUX_DIR/arch/x86/boot/bzImage" "$KERNEL_FILE"
fi

# build the initramfs
pushd "$SCRIPT_DIR"
if ! [ -f "$INITRD_MANUAL_FILE" ]; then
    echo "# Create manual initramfs"
    bash "$INITRD_SCRIPT" --share --cwd "/mnt/" --out "$INITRD_MANUAL_FILE" --force
fi
if ! [ -f "$INITRD_EVAL_FILE" ]; then
    echo "# Create eval initramfs"
    bash "$INITRD_SCRIPT" --share --cwd "/mnt/" --out "$INITRD_EVAL_FILE" --force --init "$SCRIPT_DIR/init-eval.sh"
fi
popd

# generate a fresh secret
if (! [ -f "$SECRET_FILE" ]) || $eval; then
    echo "# Generate fresh secret"
    random_string $secret_size $secret_size > "$SECRET_FILE"
fi

if (! [ -f "$QCOW_FILE" ]) || $eval; then
    echo "# Create a new encrypted disk"
    qemu-img create -f qcow2 -o encrypt.format=luks -o "encrypt.key-secret=$QCOW_SECRET_NAME" --object "secret,id=$QCOW_SECRET_NAME,file=$SECRET_FILE" "$QCOW_FILE" 0.1G
fi

echo "# Build the kernel modules for the guest machine"
if ! [ -f "$MODSYM_FILE" ]; then
    make -C "$LINUX_DIR" -j "$(nproc)" modules
fi
make -C "$UARF_DIR" kmods KDIR="$LINUX_DIR" KBUILD_MODPOST_WARN=1
cp -v "$UARF_DIR/kmods/pi/pi.ko" "$UARF_DIR/kmods/rap/rap.ko" "$ATTACK_DIR"

echo "# build the attack"
make -C "$UARF_DIR"
make -C "$ATTACK_DIR"

taskset -c 6 qemu-system-x86_64 \
    -m 8G \
    -cpu host,kvm=on \
    -enable-kvm \
    -kernel "$KERNEL_FILE" \
    -initrd "$initrd_file" \
    -virtfs local,path="$ATTACK_DIR",mount_tag=host0,security_model=mapped \
    -append "quiet console=ttyS0 nokaslr nosmep nosmap noexec=off default_hugepagesz=1G hugepages=2" \
    -nographic \
    -object "secret,id=$QCOW_SECRET_NAME,file=$SECRET_FILE" \
    -drive "file=$QCOW_FILE,format=qcow2,if=virtio,encrypt.format=luks,encrypt.key-secret=$QCOW_SECRET_NAME" \
    -object "secret,id=distracting_secret,data=$(random_string 1 8192)" \
    -object "secret,id=some_other_secret,data=$(random_string 1 8192)"
    # these last secrets are just for fun, distraction and to try to make the secret be located at unpredictable
    # offsets in the heap relative to the root object because where would be the fun otherwise?

