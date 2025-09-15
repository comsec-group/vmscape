# Kernel helper

KERNEL_REMOTE="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"

# Packages required to build Linux on Ubuntu
# But sadly nobody on earth knows that is actually required
KERNEL_DEP_PKGS="libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf dwarves libdw-dev debhelper-compat"


# Get the kernel source and ensure the required reference exists
function kernel_prepare_src() {
    local kernel_path=$1
    local kernel_ref=$2
    log_info "Prepare the kernel source"

    if [ ! -d "$kernel_path" ]; then
        log_info "Kernel does not exist at '$kernel_path'. Cloning it"
        git clone "$KERNEL_REMOTE" "$kernel_path"
    fi

    cd "$kernel_path"

    if [ -n "$(git status --porcelain)" ]; then
        log_err "Kernel at '$kernel_path' is not clean. Please commit/restore/stash everything and repeat. Exit"
        return 1
    fi

    # Ensure ref exists in local tree
    if ! git cat-file -t "$kernel_ref" > /dev/null 2>&1 ; then
        log_err "Required ref '$kernel_ref' is not present in local kernel tree. Probably fetching upstream is sufficient. Exit"
        return 1
    fi

    # # Check if already on right commit
    # if [[ $(git rev-parse HEAD) == "$kernel_ref" ]]; then
    #     return 0
    # fi

    git checkout "$kernel_ref" --quiet

    # # Clean after switching to commit
    # log_debug "Clean local tree, just to be sure."
    # make mrproper
    return 0
}

# Generate .config based on host system
function kernel_config_host() {
    local kernel_path=$1
    log_info "Configuring kernel based on host system"

    cd "$kernel_path"

    src_cfg="/boot/config-$(uname -r)"
    if [ ! -f "$src_cfg" ]; then
        log_err "Could not find host configuration file '$src_cfg'. Exit"
        exit 1
    fi

    cp "$src_cfg" .config

    log_debug "Patching config"
    make olddefconfig
    # Required to make the compilation not fail
    scripts/config --disable SYSTEM_TRUSTED_KEYS
    scripts/config --disable SYSTEM_REVOCATION_KEYS
    scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
    scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS ""
}

# Configure kernel for use in kvm guest
function kernel_config_guest() {
    local kernel_path=$1
    log_info "Configuring kernel for kvm guest"

    cd "$kernel_path"
    rm -fr .config
    make x86_64_defconfig
    make kvm_guest.config
}

# Compile the kernel
function kernel_build() {
    local kernel_path=$1
    local build_name=$2

    log_info "Compiling kernel"

    cd "$kernel_path"

    # TODO: is fakeroot required?
    # fakeroot make LOCALVERSION=-"$KERNEL_BUILD_NAME" -j `nproc`

    make deb-pkg LOCALVERSION=-"$build_name" -j $(nproc)
}
