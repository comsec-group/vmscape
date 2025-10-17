#!/bin/env bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
ATTACK_DIR="$SCRIPT_DIR/../attack"

KERNEL_FILE="$SCRIPT_DIR/bzImage"
INITRD_MANUAL_FILE="$SCRIPT_DIR/initramfs-base.cpio.gz"
INITRD_EVAL_FILE="$SCRIPT_DIR/initramfs-eval.cpio.gz"
SECRET_FILE="$SCRIPT_DIR/secret.txt"
DEFAULT_SECRET_SIZE=4096

QCOW_SECRET_NAME="disk_key"
QCOW_FILE="$SCRIPT_DIR/enc.qcow2"

# default args
eval=false
initrd_file="$INITRD_MANUAL_FILE"
secret_size="$DEFAULT_SECRET_SIZE"
core=6

function usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "       --initramfs        Use a specific initramfs."
    echo "       --core             Run VM on specific core."
    echo "       --demo             Run VM in demo mode with a shorter secret."
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

PARSED_ARGUMENTS=$(getopt --name "$0" --options=h --longoptions demo,eval,help,initramfs:,core: -- "$@")
VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" != "0" ]; then
    echo "Invalid argument"
    usage
    exit 1
fi

eval set -- "$PARSED_ARGUMENTS"
while [ "$#" -gt 1 ]; do
    case "$1" in
        --core)
            shift
            core="$1"
            shift
            ;;
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
        --initramfs)
            shift
            initrd_file="$1"
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

# generate a fresh secret
if (! [ -f "$SECRET_FILE" ]) || $eval; then
    echo "# Generate fresh secret"
    random_string $secret_size $secret_size > "$SECRET_FILE"
fi

if (! [ -f "$QCOW_FILE" ]) || $eval; then
    echo "# Create a new encrypted disk"
    qemu-img create -f qcow2 -o encrypt.format=luks -o "encrypt.key-secret=$QCOW_SECRET_NAME" --object "secret,id=$QCOW_SECRET_NAME,file=$SECRET_FILE" "$QCOW_FILE" 0.1G
fi

taskset -c "$core" qemu-system-x86_64 \
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

