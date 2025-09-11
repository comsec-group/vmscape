#!/bin/bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
BASE_DIR="$SCRIPT_DIR/.."
CONTAINER_DIR="$SCRIPT_DIR/container-ubuntu-questing"

USER_NAME="$(id -un)"
USER_ID="$(id -u)"
GROUP_ID="$(id -g)"
KVM_NAME="kvm"
KVM_ID="$(getent group "$KVM_NAME" | cut -d: -f3)"

function run-nspawn() {
    sudo systemd-nspawn \
        -D "$CONTAINER_DIR" \
        --bind "$BASE_DIR":/workspace \
        --chdir /workspace/vmscape \
        --capability=all \
        --bind /dev/kvm \
        --bind /dev/net/tun \
        --bind /dev/fuse \
        --bind /dev/loop-control \
        "$@"
}

if ! [ -d "$CONTAINER_DIR" ]; then
    # install container dependencies
    sudo apt install debootstrap systemd-container

    # bootstrap the ubuntu
    sudo debootstrap \
        --arch amd64 \
        --variant minbase \
        --include sudo,tmux,vim,git,wget,cpio,ca-certificates,build-essential,libncurses-dev,bison,bc,flex,libssl-dev,libelf-dev,fakeroot \
        questing "$CONTAINER_DIR" http://archive.ubuntu.com/ubuntu/

    # qemu with the right version 
    run-nspawn -- sudo apt install -y \
        ./guest/qemu/qemu-system-common_10.0.2+ds-1ubuntu2_amd64.deb \
        ./guest/qemu/qemu-system-x86_10.0.2+ds-1ubuntu2_amd64.deb \
        ./guest/qemu/qemu-utils_10.0.2+ds-1ubuntu2_amd64.deb

    # for debugging
    run-nspawn -- sudo apt install -y \
        gdb \
        ./guest/qemu/qemu-system-x86-dbgsym_10.0.2+ds-1ubuntu2_amd64.ddeb

    # create user and group matching host to avoid file permissions issues
    run-nspawn -- groupadd \
        --gid "$GROUP_ID" \
        "$USER_NAME"

    run-nspawn -- groupadd \
        --gid "$KVM_ID" \
        "$KVM_NAME"

    run-nspawn -- useradd \
        --uid "$USER_ID" \
        --gid "$GROUP_ID" \
        -G "$KVM_NAME" \
        -m \
        "$USER_NAME"

    # give the user in the container sudo access
    echo "$USER_NAME ALL=(ALL:ALL) NOPASSWD: ALL" | \
        sudo tee -a "$CONTAINER_DIR/etc/sudoers.d/$USER_NAME"

    # we somehow needed this for DNS to work
    sudo rm -v "$CONTAINER_DIR/etc/resolv.conf"
    sudo cp -v /etc/resolv.conf "$CONTAINER_DIR/etc/resolv.conf"

    # for debugging install ddebs repo and the gdb and qemu debug packages
fi

run-nspawn --user "$USER_NAME" -- bash
