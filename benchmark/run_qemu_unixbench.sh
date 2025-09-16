#!/bin/bash

set -e
set -u

exec 3>&1

SCRIPT_DIR="$(realpath "$(dirname "$0")")"

VM_DRIVE_FILE="$SCRIPT_DIR/bookworm.img"
MOUNT_DIR="$SCRIPT_DIR"
KERNEL_BUILD_NAME="vmscape" # TODO: Change
KERNEL_FILE="$SCRIPT_DIR/bzImage"

PKGS="qemu qemu-kvm"

QEMU_ELF="${QEMU_ELF:-qemu-system-x86_64}"

DRIVE_IMG="$SCRIPT_DIR/bookworm.img"

UNIXBENCH_REMOTE="https://github.com/kdlucas/byte-unixbench"
UNIXBENCH_PATH="$SCRIPT_DIR/unixbench"

PID_FILE="/tmp/$(whoami)/vm.pid"
mkdir -p "/tmp/$(whoami)"

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

if [ ! -d "$UNIXBENCH_PATH" ]; then
    log_debug "Getting unixbench"
    git clone "$UNIXBENCH_REMOTE" $UNIXBENCH_PATH
    cd $UNIXBENCH_PATH/UnixBench
    make -j `nproc`
fi

if [ ! -f "$KERNEL_FILE" ]; then
    log_err "Kernel image does not exist at '$KERNEL_FILE'. Please get one"
    exit 1
fi

QEMU_RAM="4G"

if [ -f $PID_FILE ]; then
    kill $(cat $PID_FILE)
fi

log_info "Starting VM"

args=(
    -m $QEMU_RAM
    # It does not like to run on SMT on cn151
    -smp cpus=1,maxcpus=1,dies=1,cores=1,threads=1
    # -smp cpus=2,maxcpus=2,dies=1,cores=1,threads=2
    -kernel "$KERNEL_FILE"
    # root may need to be adjusted, if boot fails
    -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0"
    -drive file="$DRIVE_IMG",format=raw
    -enable-kvm
    -nographic
    -pidfile $PID_FILE
    # Shared Folder
    -virtfs local,path="$SCRIPT_DIR",mount_tag=host0,security_model=mapped
    # # SATA Drive
    # -device ahci,id=ahci0
    # -drive file=chunk2.img,if=none,format=raw,id=hd1
    # -device ide-hd,drive=hd1,bus=ahci0.0
    # # Virtio Drive
    # -device virtio-blk-pci,drive=hd0
    # -drive file=chunk.img,if=none,format=raw,id=hd0
    # # Vhost Drive
    # # -device vhost-scsi
    # # Usermode netowrking, for SSH
    # # -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22
    # # -net nic,model=e1000
)

taskset -c 5 $QEMU_ELF "${args[@]}" 2>&1 | tee vm.log
