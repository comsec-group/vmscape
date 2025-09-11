!#/usr/bin/env bash

# Apply a set of `PATCHES` on top of `KERNEL_PARENT` on branch `KERNEL_PATCHED`

set -u
set -e
set -x

exec 3>&1

KERNEL="$HOME/LinuxKernelTorvalds"
KERNEL_PARENT="v6.8"
KERNEL_BASE="${KERNEL_PARENT}_base"
KERNEL_PATCHED="${KERNEL_PARENT}_patched"

declare -a PATCHES=("$HOME/uARF/linux/0001-Add-IBPB-on-vmexit.patch")

# All packages that are required for building a kernel on Ubuntu
# But sadly nobody on earth knows that is actually required
# PKGS="linux-image-unsigned-$(uname -r) libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf llvm"
PKGS="libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf llvm dwarves"

verbose=false

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
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options"
    echo "  -v, --verbose   Show verbose output."
    echo "  -h, --help      Show this help menu."
    echo "  -f, --force     Redo setup if already done."
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
        *)
            log_err "Invalid option \"$1\". Exit"
            usage
            exit 1
            ;;
    esac
done

sudo apt-get install $PKGS

if [ ! -d "$KERNEL" ]; then
    log_err "Kernel does not exist: '$KERNEL'. Exit"
    exit 1
fi

cd "$KERNEL"

if [ -n "$(git status --porcelain)" ]; then
    log_err "Linux is not clean. Exit"
    exit 1
fi

# Create base if not exists
if ! git show-ref --quiet "refs/heads/$KERNEL_BASE"; then
    log_info "Base branch '$KERNEL_BASE' does not exist yet, creating"
    git checkout "$KERNEL_PARENT"
    git switch -c "$KERNEL_BASE"
fi

git switch "$KERNEL_BASE"

# Create patched if not exists
if ! git show-ref --quiet "refs/heads/$KERNEL_PATCHED"; then
    log_info "Patched branch '$KERNEL_PATCHED' does not exist yet, creating"
    git switch -c "$KERNEL_PATCHED"

    log_info "Applying patches"
    for e in "${PATCHES[@]}"; do
        if [ ! -f $e ]; then
            log_err "Patch $e does not exist. Exit"
            exit 1
        fi
        log_debug "Apply $e"
        git apply --check $e
        git am --quiet < $e
    done
fi

git switch "$KERNEL_PATCHED"

rm -rf .config

# Configure kernel
if [ ! -f ".config" ]; then
    log_info "Creating config"
    src_cfg="/boot/config-$(uname -r)"
    if [ ! -f "$src_cfg" ]; then
        log_err "Config '$src_cfg' does not exist. Exit"
        exit 1
    fi

    log_debug "Copy config"
    cp "$src_cfg" .config
    if [ ! -f ".config" ]; then
        log_er "Failed to copy config. Exit"
        exit 1
    fi

    log_debug "Fix config"
    make olddefconfig
    sed -iE 's/="[^"]*\.pem"/=""/g' .config
    # sed -i 's/^CONFIG_MODULE_SIG=y$/CONFIG_MODULE_SIG=n/' .config
    sed -i 's/^CONFIG_MODULE_SIG_ALL=y$/CONFIG_MODULE_SIG_ALL=n/' .config
    grep CONFIG_MODULE_SIG .config
fi

genkey="x509.genkey"
if [ ! -f "$genkey" ]; then
    log_info "Create genkey '$genkey'"
    cat >$genkey <<EOL
[ req ]
default_bits = 4096
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
CN = Modules

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOL
fi

pem_key="signing_key.pem"
if [ ! -f "$pem_key" ]; then
    log_info "Creating keys"
    openssl req -new -nodes -utf8 -sha512 -days 36500 -batch -x509 -config x509.genkey -outform DER -out signing_key.x509 -keyout signing_key.pem
fi

# TODO: Only build if required!

name="ibpbonvmexit2"

make clean
make LOCALVERSION=-$name -j `nproc`
make modules LOCALVERSION=-$name -j `nproc`
sudo make modules_install LOCALVERSION=-$name
sudo make install LOCALVERSION=-$name

# git switch $KERNEL_BASE
# # TODO: Can we do without clean?
# make clean
#
# name="custombase"
# make LOCALVERSION=-$name -j `nproc`
# make modules LOCALVERSION=-$name -j `nproc`
# sudo make modules_install LOCALVERSION=-$name
# sudo make install LOCALVERSION=-$name

log_info "Done"
