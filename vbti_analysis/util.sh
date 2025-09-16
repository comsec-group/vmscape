# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
RESET="\033[0m"

function log_debug() {
    if [ "$verbose" = true ]; then
        printf "${BLUE}[DEBUG]${RESET} %s\n" "$*" 1>&3
    fi
}

function log_info() {
    printf "${GREEN}[INFO]${RESET} %b\n" "$*" 1>&3
}

function log_err() {
    printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2
}

# Ensure the system complies with our tested systems and that KVM is available
function verify_system() {
    log_info "Verifying your system."

    if [ $(uname) != "Linux" ]; then
        log_err "Well, well, well."
        return 1
    fi

    if [ ! -f "/etc/os-release" ]; then
        log_err "Unknown system."
        return 1
    fi

    if (
        . /etc/os-release
        [[ "${NAME:-}" != "Ubuntu" || "${VERSION_ID:-}" != "24.04" ]]
        ); then
        log_err "System is not running Ubuntu 24.04."
        return 1
    fi

    if [ ! -c /dev/kvm ]; then
        log_err "KVM not available."
        return 1
    fi

    if [ ! -w /dev/kvm ]; then
        log_err "No permissions to access KVM. Add yourself to the KVM group."
        return 1
    fi

    log_info "Valid Ubuntu 24.04 system with KVM detected"
}

function user_confirms() {
    read -p "Shall we proceed? [y/N] " -r
    [[ $REPLY =~ ^[Yy]$ ]]
}
