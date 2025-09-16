#!/usr/bin/env bash

# Compile QEMU with or without retpoline.

set -u
set -e

exec 3>&1

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
cd "$SCRIPT_DIR"

QEMU_PATH="${QEMU_PATH:-$SCRIPT_DIR/QEMU}"
QEMU_BUILD_PATH="$QEMU_PATH/build"
QEMU_REMOTE="https://gitlab.com/qemu-project/qemu.git"
QEMU_REF="v8.2.2"

QEMU_BIN="$SCRIPT_DIR/qemu-system-x86_64"

PKGS="python3-venv python3-sphinx python3-sphinx-rtd-theme ninja-build libglib2.0-dev libgcrypt20-dev zlib1g-dev autoconf automake libtool bison flex libpixman-1-dev"

function log_debug() {
    if [ "$verbose" = true ]; then
        printf "$(date +"%H:%M:%S") $* \n" 1>&3
    fi
}

function log_info() {
    printf "$* \n" 1>&3
}

function log_err() {
    printf "$(date +"%H:%M:%S") ERROR: $* \n" >&2
}

function usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options"
    echo "  -r, --retpoline Build with retpoline."
    echo "  -v, --verbose   Show verbose output."
    echo "  -h, --help      Show this help menu."
    # echo "  -f, --force     Redo setup if already done."
}

function user_confirms() {
    read -p "Shall we proceed? [y/N] " -r
    [[ $REPLY =~ ^[Yy]$ ]]
}

verbose=false
build_retpoline=false
force=false

while [ "$#" -gt 0 ]; do
    case $1 in
        -r|--retpoline)
            build_retpoline=true
            QEMU_BUILD_PATH="${QEMU_BUILD_PATH}_retpoline"
            shift
            ;;
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
        *)
            log_err "Invalid option \"$1\". Exit"
            usage
            exit 1
            ;;
    esac
done

function verify_system() {
    # Ensure the system is suitable for the artifact evaluation
    if [ ! -f "/etc/lsb-release" ] || ! grep -q "DISTRIB_RELEASE=24.04" "/etc/lsb-release"; then
        log_err "Your are supposed to run this on Ubuntu 24.04. Exit"
        exit 1
    fi
    log_debug "Valid ubuntu system"
}

function install_deps() {
    # Install deps required to build the kernel
    log_info "Installing required packages: '$PKGS'"
    user_confirms || { echo "Exit."; exit 1; }
    sudo apt-get install $PKGS
}

function prepare_qemu_src() {
    # Get the qemu source and ensure the required reference exists
    if [ ! -d "$QEMU_PATH" ]; then
        log_info "QEMU does not exist at '$QEMU_PATH'. Cloning it"
        user_confirms || { echo "Exit."; exit 1; }
        git clone "$QEMU_REMOTE" "$QEMU_PATH"
    fi

    cd "$QEMU_PATH"

    if [ -n "$(git status --porcelain)" ]; then
        log_err "Repository is not clean. Exit"
        exit 1
    fi

    # Ensure ref is there
    if ! git show-ref --quiet "refs/tags/$QEMU_REF"; then
        log_err "Ref '$QEMU_REF' does not exist. Please ensure you have a recent recent version. Exit."
        exit 1
    fi

    git checkout "$QEMU_REF"
}

function configure() {
    rm -rf "$QEMU_BUILD_PATH"
    mkdir -p "$QEMU_BUILD_PATH"
    cd "$QEMU_BUILD_PATH"
    log_info "Configuring QEMU"

    # Need to disable FCF Protection, as it conflicts with retpoline
    # Also disable it for the default build, to maintain comparability
    local cc_flags="-fcf-protection=none"

    if [[ "$build_retpoline" = true ]]; then
        cc_flags="$cc_flags -mindirect-branch=thunk -mfunction-return=thunk"
    fi

    $QEMU_PATH/configure --extra-cflags="$cc_flags" --enable-slirp
}

function compile() {
    # Compile the kernel
    cd "$QEMU_BUILD_PATH"

    log_info "Compiling QEMU"
    make -j `nproc`
}

verify_system
install_deps
prepare_qemu_src

configure
compile

if [[ ! -f "$QEMU_BUILD_PATH/qemu-system-x86_64" ]]; then
    log_err "Compilation somehow failed."
    exit 1
fi

if [[ "$build_retpoline" = true ]]; then
    ln -s "$QEMU_BUILD_PATH/qemu-system-x86_64" ${QEMU_BIN}_retpoline
    log_info "Linked QEMU binary to '${QEMU_BIN}_retpoline'"
else
    ln -s "$QEMU_BUILD_PATH/qemu-system-x86_64" $QEMU_BIN
    log_info "Linked QEMU binary to '$QEMU_BIN'"
fi

