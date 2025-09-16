#!/usr/bin/bash

# Setup script for the PoC of VM Scape

set -u
set -e
set -E
set -o pipefail

trap 'log_err "Command failed at line $LINENO: $BASH_COMMAND"; log_err "Cleanup incomplete"' ERR

exec 3>&1

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
cd "$SCRIPT_DIR"

KERNEL_PATH="${KERNEL_PATH:-$SCRIPT_DIR/LinuxKernel}"
UARF_PATH="$SCRIPT_DIR/../uARF"
KERNEL_BUILD_NAME="vmscape" # TODO: use variable from setup.sh

source "$SCRIPT_DIR/util.sh"

function usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options"
    echo "  -v, --verbose      Show verbose output."
    echo "  -h, --help         Show this help menu."
}

verbose=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit
            ;;
        -v|--verbose)
            verbose=true
            shift
            ;;
        *)
            log_err "Invalid option \"$1\". Exit"
            usage
            exit 1
            ;;
    esac
done

function uninstall_kernels() {
    local build_name=$1
    log_info "Uninstall custom kernels."
    # Grep fails if it matches nothing
    kernels=$(dpkg --list | egrep 'linux-image|linux-headers' | grep "$build_name" | awk '{print $2}' | tr '\n' ' ' || true)
    if [ -z "$kernels" ]; then
        log_info "No kernels to uninstall"
        return 0
    fi
    log_info "Uninstalling kernels: \n$(echo $kernels | tr ' ' '\n')"
    user_confirms || { log_info "Not removing any kernels."; return 0; }
    sudo dpkg --purge $kernels
}

log_info "Uninstalling uARF. Requiring sudo"
sudo make -C "$UARF_PATH" uninstall
uninstall_kernels "$KERNEL_BUILD_NAME"
log_info "Cleanup done."
