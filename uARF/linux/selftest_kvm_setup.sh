#!/bin/bash

##
# KVM Selftest Setup
#
# Automises the setup of the KVM selftest of the Linux Kernel.
##

set -e

# Open a new file descriptor that redirects to stdout:
# For logging
exec 3>&1

# Path to root of linux kernel repo
LINUX_PATH="${LINUX_PATH:-$HOME/LinuxKernelTorvalds}"
LINUX_REMOTE="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
KVM_SELFTEST_PATH="${LINUX_PATH}/tools/testing/selftests/kvm"
SELFTEST_REVENG_PATH="${KVM_SELFTEST_PATH}/x86_64/rev_eng"

# Path to root of uARF repo
UARF_PATH="${UARF_PATH:-$HOME/uARF}"
# Ref at which we do the testing
UARF_REF="f7d9cfc6c83c63673d8d61b2fec29a627bf072c2"

# Enable only after reading potential globals
set -u

# Array of patches to apply
declare -a UARF_PATCHES=( \
        "${UARF_PATH}/linux/patches/0001-Integrate-uARF-framework-and-adjust-for-ASM-support.patch" \
        "${UARF_PATH}/linux/patches/0002-Add-support-for-guest-user.patch" \
    )

UARF_TEST="${UARF_PATH}/tests/exp_guest_bti.c"

# Branch name to apply patches to
KERNEL_BR_NAME="UARF_SELFTEST"

# Git ref to apply patches to
KERNEL_REF="tags/v6.6"

verbose=true
force=false
declare -a tests=()

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
    echo "Positional Arguments"
    echo "  SELFTESTS       Tests to add (default: $UARF_TEST)."
    echo ""
    echo "Global Variables"
    echo "  LINUX_PATH      Path to linux repo (current: $LINUX_PATH)"
    echo "  UARF_PATH       Path to uARF repo (current: $UARF_PATH)"
    echo ""
}

while [ "$#" -gt 0 ]; do
    case $1 in
        -h|--help)
            usage
            exit ;;
        -f|--force)
            force=true
            shift
            ;;
        -v|--verbose)
            verbose=true
            shift
            ;;
        -*)
            log_err "Invalid option \"$1\""
            usage
            exit 1
            ;;
        *)
            test_cand=$(readlink -f $1)
            if [ ! -f $test_cand ]; then
                log_err "Test $test_cand does not exist"
                exit 1
            fi
            log_debug "Receive module $test_cand"
            tests+=$test_cand
            shift
            ;;
    esac
done

# Undo all changed done by the setup script.
function rollback_kernel() {
    log_info "Rollback kernel"
    cd $LINUX_PATH
    git restore . --quiet
    git clean -dfx --quiet
    git checkout $KERNEL_REF --quiet
    git branch -D $KERNEL_BR_NAME --quiet &>/dev/null || true
}

### TODO: Verify system configuration?

###
# Verify uARF repo
###

log_info "Verify uARF repo at '$UARF_PATH'"
if [ ! -d "$UARF_PATH" ]; then
    log_err "Repo does not exist. Exit"
    exit 1
fi

cd "$UARF_PATH"
# if ! git rev-parse --git-dir > /dev/null 2>&1; then
#     log_err "uARF is not a valid git repo. Exit"
#     exit 1
# fi

# if [ -n "$(git status --porcelain)" ]; then
#     log_err "uARF is not clean. Exit"
#     exit 1
# fi

# if ! git checkout $UARF_REF > /dev/null 2>&1; then
#     log_err "uARF is of the wrong version. Exit"
#     exit 1
# fi

###
# Compile uARF library, pi and rap
###

cd "$UARF_PATH"
log_info "Compile uARF library, pi and rap"

log_debug "Clean repo"
make clean > /dev/null

log_debug "Compile libuarf.a"
make libuarf.a > /dev/null

if [ ! -f "libuarf.a" ]; then
    log_err "Failed to compile 'library.a'"
    exit 1
fi

log_debug "Compile kernel modules"

PI_PATH="$UARF_PATH/kmods/pi/pi.ko"
KDIR=/lib/modules/$(uname -r)/build make -C "$UARF_PATH/kmods" "$PI_PATH"
if [ ! -f "$PI_PATH" ]; then
    log_err "Failed to compile pi.ko. Exit"
    exit 1
fi

RAP_PATH="$UARF_PATH/kmods/rap/rap.ko"
KDIR=/lib/modules/$(uname -r)/build make -C "$UARF_PATH/kmods" "$RAP_PATH"
if [ ! -f "$RAP_PATH" ]; then
    log_err "Failed to compile rap.ko. Exit"
    exit 1
fi

###
# Get Linux Kernel
###

log_info "Get Linux Kernel"

if [ ! -d "$LINUX_PATH" ]; then
    log_info "Linux kernel not at '$LINUX_PATH', cloning"
    git clone "$LINUX_REMOTE" "$LINUX_PATH"
fi

cd "$LINUX_PATH"
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    log_err "Linux is not a valid git repo. Exit"
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    log_err "Linux is not clean. Exit"
    # exit 1
    # TODO: somehow protect this
    # rollback_kernel
fi

###
# Patch Selftest Infrastructure
###

# Apply all patches in $UARF_PATCHES to the kernel and fix some links
function patch_selftest() {
    cd "$LINUX_PATH"

    log_debug "Create testing branch $KERNEL_BR_NAME at ref $KERNEL_REF"
    git checkout $KERNEL_REF -b $KERNEL_BR_NAME --quiet

    log_debug "Applying patches:"
    for e in "${UARF_PATCHES[@]}"; do
        if [ ! -f $e ]; then
            log_err "Patch $e does not exist"
            exit 1
        fi
        git apply --check $e
        git am --quiet < $e
    done

    log_debug "Fixing paths"
    cd "$KVM_SELFTEST_PATH/include"
    rm -rf uarf
    ln -s "$UARF_PATH/include" uarf

    cd "$KVM_SELFTEST_PATH/lib"
    rm -rf uarf
    ln -s "$UARF_PATH/" uarf

    git add "$KVM_SELFTEST_PATH"
    git commit -m "Fix include and lib paths" --quiet
}

log_info "Patch Selftest Infrastructure"

# Check if setup has already been done
cd "$LINUX_PATH"
if git show-ref --quiet refs/heads/$KERNEL_BR_NAME; then
    log_debug "Patching selftest"
    if [ "$force" = true ]; then
        log_debug "Redo patching of selftest"
        rollback_kernel
        patch_selftest
    else
        log_debug "Selftest has already been patched. Skip"
    fi
else
    patch_selftest
fi

###
# Add selftest
###

# Add a single selftest provided as $1 (.c file) to the infrastructure and register it in the Makefile
# $1 is the .c file
function add_selftest() {
    local file=$(basename -- $1)
    log_debug "\t$1 ($file)"

    if [ ! -f $1 ]; then
        log_err "File $1 does not exist"
        exit 1;
    fi

    mkdir -p "$SELFTEST_REVENG_PATH"
    cd "$SELFTEST_REVENG_PATH"

    if [ -f $file ]; then
        log_debug "A test with the name $file has already been added. Skip"
        return
    fi

    ln -s "$1" "$file"
    git add "$file"

    local file_path="x86_64/rev_eng/${file%.c}"

    cd "$KVM_SELFTEST_PATH"
    sed -i "/# TEST_GEN_FILES += x86_64\/rev_eng\/hello_world_asm.o/a TEST_GEN_PROGS_x86_64 += ${file_path}" Makefile
    git add Makefile

    git commit -m "Add test ${file}"
}

log_info "Add selftests"

if [ ${#tests[@]} -eq 0 ]; then
    log_debug "No test was provided, using default"
    add_selftest $UARF_TEST
else
    for e in "${tests[@]}"; do
        add_selftest $e
    done
fi

###
# Compile selftest infrastructure
###

log_info "Compile selftests"

cd "$LINUX_PATH"
make headers -j $(nproc)

cd "$KVM_SELFTEST_PATH"
make -j $(nproc)

###
# Load pi and rap kernel moduels
###

# (Re-)Loads the kernel moduel, whose path (to .ko) is provided as $1
function reload_module() {
    module_path=$1
    module_file=$(basename -- "$1")
    module_name="${module_file%.*}"

    log_debug "(Re-)Loading module '$module_name' at '$module_path'"

    if [ -z "$module_path" ]; then
        log_err "No module at '$module_path'. Exit"
        exit 1
    fi

    if lsmod | grep -qE "^$module_name\s+"; then
        if [ "$force" = false ]; then
            log_debug "Module '$module_name' is loaded. Nothing to do..."
            return
        fi
        log_debug "Module '$module_name' is loaded. Removing it..."
        log_info "rmmod requires root. May prompt for password"
        sudo rmmod $module_name
        out=$?
        if [ $out -ne 0 ]; then
            log_err "Failed to remove '$module_name'. Exit"
            exit 1
        fi
    fi
    log_info "insmod requires root. May prompt for password"
    sudo insmod $module_path
    out=$?
    if [ $out -ne 0 ]; then
        log_err "Failed to load module '$module_name'. Exit"
        exit 1
    fi

    if ! lsmod | grep -qE "^$module_name\s+"; then
        log_err "Failed to reload module 'module_name'. Exit"
        exit 1
    fi

    log_debug "Module '$module_name' has been (re)loaded"
}

reload_module $PI_PATH
reload_module $RAP_PATH

###
# KVM
###

if ! kvm-ok > /dev/null 2&>1 ; then
    log_err "Hardware virtualisation is not available. Cannot run KVM."
    exit 1
fi

if ! id -Gn | grep -qw kvm; then
    user=$(whoami)
    if [ -z "$user" ]; then
        log_err "Failed to get current user"
        exit 1
    fi
    log_debug "Addint user '$user' to group kvm"
    sudo usermod -a -G kvm $user

    log_info "########## Please sign out and in again #########"
fi

###
# Done!
###

log_info "Success: KVM selfteset infrastructure is set up!"
exit 0
