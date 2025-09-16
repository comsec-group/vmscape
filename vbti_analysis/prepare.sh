#!/usr/bin/bash

# Setup script for the PoC of VM Scape

set -u
set -e
set -E
set -o pipefail

trap 'log_err "Command failed at line $LINENO: $BASH_COMMAND"; log_err "Preparation incomplete"' ERR

exec 3>&1

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
cd "$SCRIPT_DIR"

KERNEL_BUILD_NAME="vmscape" # TODO: use variable from setup.sh

UARF_PATH="$SCRIPT_DIR/../uARF"

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

# Verify that the currently running kernel contains $1
function verify_kernel() {
    local build_name=$1
    log_info "Verify running kernel."
    uname -r | grep -q "$build_name"
}

# Reload the uarf module $1
function load_module() {
    module_name=$1
    module_file=$module_name.ko
    module_path=$(find "$UARF_PATH" -name $module_file -exec realpath {} \;)

    if [ -z "$module_path" ]; then
        log_err "No file named $module_file found in $UARF_PATH"
        exit 1
    fi

    # TODO: For some reason this does not work with -q for me
    if lsmod | grep -E "^${module_name}[[:space:]]+" > /dev/null; then
        log_debug "Module '$module_name' is already loaded."
        return 0
    fi

    log_debug "Loading '$module_name' from '$module_path'"

    sudo insmod "$module_path"

    if ! lsmod | grep -E "^${module_name}[[:space:]]+" > /dev/null; then
        log_err "Insmod did not fail but module not loaded. Should not happen."
        exit 1
    fi
}

if ! verify_system; then
    log_err "Your system does not confirm with our verified setup. It could still work, but you would be on your own..."
    user_confirms || { echo "Exit."; exit 5; }
    log_info "Best of luck..."
fi

# if ! verify_kernel "$KERNEL_BUILD_NAME"; then
#     log_err "You are not using the correct kernel. It could still work, but you would be on your own..."
#     user_confirms || { echo "Exit."; exit 5; }
#     log_info "Best of luck..."
# fi

# Required to rebuild as they need to match kernel version
log_info "Build custom kernel modules"
make -C "$UARF_PATH" kmods -j "$(nproc)"

log_info "Load custom kernel modules. Requires sudo."
load_module "pi"
load_module "rap"

log_info "Preparations complete."
