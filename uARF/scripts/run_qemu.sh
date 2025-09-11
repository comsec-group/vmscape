#!/bin/bash

# Open a new file descriptor that redirects to stdout:
# For logging
exec 3>&1

# Default configurations
CWD=$(pwd)
SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

KERNEL="${SCRIPTPATH}/bzImage"
INITRAMFS="${SCRIPTPATH}/initramfs.cpio.gz"
QEMU_EXEC=qemu-system-x86_64

share_dir=""
gdb=false
verbose=false
declare -a traces
print=false

function log() {
    if [ "$verbose" = true ]; then
        printf "$(date +"%H:%M:%S") $* \n" 1>&3
    fi
}

function log_err() {
    printf "$(date +"%H:%M:%S") ERROR: $* \n" >&2
}

function usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -k <kernel>       Path to kernel image (default: $KERNEL)"
    echo "  -i <initramfs>    Path to initramfs (default: $INITRAMFS)"
    echo "  -s <share_dir>    Path to shared directory (default: NONE)"
    echo "  -g                Use GDB and block"
    echo "  -t <trace>        Attach a trace (multiple possible)"
    echo "  -q <QEMU_ELF>     Path to Qemu executable (default: $QEMU_EXEC)"
    echo "  -v                Verbose printing"
    echo "  -p                Print the full QEMU command without running it"
    echo "  -h                Show this help message"
    exit 1
}

# Parse options
while getopts "k:i:s:gt:q:vph" opt; do
    case $opt in
        k) KERNEL=$OPTARG ;;
        i) INITRAMFS=$OPTARG ;;
        s) share_dir=$OPTARG ;;
        g) gdb=true ;;
        t) traces+=($OPTARG) ;;
        q) QEMU_EXEC=$OPTARG ;;
        v) verbose=true ;;
        p) print=true ;;
        h) usage ;;
        *)  echo "Invalid option"
            usage ;;
    esac
done

function get_qemu_args() {
    log "Composing qemu args"
    local -n args=$1
    # Somehow qemu wants that the arguments and their values are separated...
    # TODO: Assert KVM is available
    args=("-nographic" "-m" "512" "-cpu" "host,kvm=on" "-enable-kvm")

    # Validate inputs
    if [ ! -f "$KERNEL" ]; then
        log_err "Kernel image not found at '$KERNEL'"
        exit 1
    fi
    args+=("-kernel" "$KERNEL")

    if [ ! -f "$INITRAMFS" ]; then
        log_err "Initramfs not found at '$INITRAMFS'"
        exit 1
    fi
    args+=("-initrd" "$INITRAMFS")

    if [ $gdb == "true" ]; then
        args+=("-gdb" "tcp::1234" "-S")
    fi

    if [ -n "$share_dir" ]; then
        if [ ! -d "$share_dir" ]; then
            log_err "Share dir not found at '$share_dir'"
            exit 1
        fi
        args+=("-virtfs" "local,path=$share_dir,mount_tag=host0,security_model=mapped")
    fi

    for e in "${traces[@]}"; do
        args+=("--trace" "\"$e\"")
    done

    args+=("-append" "\"console=ttyS0 nokaslr nosmep nosmap randomize_va_space=0 noexec=off\"")

    args+=("-D" "bla.bla")
}

declare -a qemu_args
get_qemu_args qemu_args
log "qemu args:" `declare -p qemu_args`

log "Run VM with args ${qemu_args[@]}"

if [ $print == "true" ]; then
    echo "$QEMU_EXEC ${qemu_args[@]}"
else
    $QEMU_EXEC "${qemu_args[@]}"
fi

    # -kernel "$KERNEL" \
    # -initrd "$INITRAMFS" \
    # -nographic \
    # -append "console=ttyS0 nokaslr nosmep nosmap randomize_va_space=0 noexec=off" \
    # -m 512 \
    # -cpu host \
    # -enable-kvm \
    # -gdb tcp::1234 \
    # -S
    # # -virtfs local,path=$SHARE_DIR,mount_tag=host0,security_model=mapped
