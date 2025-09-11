#!/bin/bash

set -e
set -u

exec 3>&1

CWD=$(pwd)

UARF_PATH="${UARF_PATH:-$HOME/uARF}"
GEN_DRIVE="$UARF_PATH/scripts/gen_debian_drive.sh"

DRIVE_PATH="$HOME/benchmark_drive"
DRIVE_IMG="$DRIVE_PATH/bookworm.img"
DRIVE_RSA_PUB="$DRIVE_PATH/bookworm_misc/bookworm.is_rsa"

UNIXBENCH_REMOTE="https://github.com/kdlucas/byte-unixbench"
UNIXBENCH_PATH="$HOME/unixbench"

KERNEL_IMG_PATH="$UARF_PATH/benchmark/bzImage"

# QEMU_ELF="qemu-system-x86_64"
QEMU_ELF="$HOME/qemu/build_retpoline/qemu-system-x86_64"
# QEMU_ELF="$HOME/qemu/bin/qemu-system-x86_64"

verbose=false
force=false

function log_debug() {
    if [ "$verbose" = true ]; then
        printf "$(date +"%H:%M:%S") $* \n" 1>&3
    fi
}

function log_info() {
    printf "$(date +"%H:%M:%S") $* \n" 1>&3
}

function log_err() {
    printf "$(date +"%H:%M:%S") ERROR: $* \n" >&2
}

function usage() {
    echo "Usage: $0 [OPTIONS] [SELFTESTS]"
    echo ""
    echo "Options"
    echo "  -h, --help      Show this help menu."
    echo "  -f, --force     Redo setup if already done."
    echo "  -v, --verbose   Show verbose output."
    echo ""
    echo "Global Variables"
    echo "  UARF_PATH       Path to uARF repo (current: $UARF_PATH)"
    echo ""
}

PARSED_ARGUMENTS=$(getopt --name "$0" --options=fhv --longoptions force,help,verbose -- "$@")
VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" != "0" ]; then
    echo "Invalid argument"
    usage
fi

eval set -- "$PARSED_ARGUMENTS"
while true; do
    case "$1" in
        -f|--force)
            force=true
            shift
            ;;
        -v|--verbose)
            verbose=true
            shift
            ;;
        -h|--help)
            usage
            exit 1
            ;;
        --)
            shift
            break;
            ;;
        *)
            # We check for invalid options before. So this should not happen
            echo "Should not be executed"
            exit 2
            ;;
    esac
done

log_debug "Arguments parsed"

if ! command -v debootstrap >/dev/null 2>&1 ; then
    log_err "Command 'debootstrap' not available. Please install it. Exit"
    exit 1
fi

if [ "$force" = true ]; then
    log_info "Removing all artefacts"
    rm -rf $UNIXBENCH_PATH
fi

if [ ! -f "$DRIVE_IMG" ]; then
    log_debug "Drive image '$DRIVE_IMG' does not exist. Generating it"
    $GEN_DRIVE -o "$DRIVE_PATH" -v -s
fi

if [ ! -d "$UNIXBENCH_PATH" ]; then
    log_debug "Getting unixbench"
    git clone "$UNIXBENCH_REMOTE" $UNIXBENCH_PATH
    cd $UNIXBENCH_PATH/UnixBench
    make
fi

if [ ! -f "$KERNEL_IMG_PATH" ]; then
    log_err "Kernel image does not exist at '$KERNEL_IMG_PATH'. Please get one"
    exit 1
fi

QEMU_RAM="4G"

# echo qemu-system-x86_64 -m $QEMU_RAM -cpu host,kvm=on -enable-kvm -kernel "$KERNEL_IMG_PATH" -nographic -virtfs local,path=/local/home/jegraf,mount_tag=host0,security_model=mapped -append "console=ttyS0" -initrd "$INITRAMFS_PATH"

if [ -f /tmp/jegraf/vm.pid ]; then
    kill $(cat vm.pid)
fi

mkdir -p /tmp/jegraf

log_info "Starting VM"
# qemu-system-x86_64 \
# $(QEMU_ELF) \
/local/home/jegraf/qemu/build_retpoline/qemu-system-x86_64 \
# /local/home/jegraf/qemu/build_baseline/qemu-system-x86_64 \
    -m $QEMU_RAM \
    -smp cpus=2,maxcpus=2,dies=1,cores=1,threads=2 \
    -kernel "$KERNEL_IMG_PATH" \
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
    -drive file="$DRIVE_IMG",format=raw \
    -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
    -net nic,model=e1000 \
    -enable-kvm \
    -nographic \
    -virtfs local,path="/local/home/jegraf",mount_tag=host0,security_model=mapped \
    -pidfile /tmp/jegraf/vm.pid \
    # -daemonize \
    2>&1 | tee vm.log
