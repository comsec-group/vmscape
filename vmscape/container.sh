#!/bin/bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
BASE_DIR="$SCRIPT_DIR/../"
CONTAINER_DIR="$SCRIPT_DIR/container-ubuntu-questing"

USER_NAME="$(id -un)"
USER_ID="$(id -u)"
GROUP_ID="$(id -g)"
KVM_NAME="kvm"
KVM_ID="$(getent group "$KVM_NAME" | cut -d: -f3)"

function run-nspawn() {
    sudo systemd-nspawn \
        -D "$CONTAINER_DIR" \
        --capability=all \
        --bind "$BASE_DIR":/workspace \
        --bind /dev/kvm \
        --bind /dev/net/tun \
        --bind /dev/fuse \
        --bind /dev/loop-control \
        --chdir /workspace/vmscape \
        -E "http_proxy=$http_proxy" \
        -E "https_proxy=$https_proxy" \
        "$@"
}

# prepare the actual container

if ! [ -d "$CONTAINER_DIR" ]; then
    # install container dependencies
    sudo apt install debootstrap systemd-container

    # bootstrap the ubuntu with packages needed for building the virtual machine
    sudo debootstrap \
        --arch amd64 \
        --variant minbase \
        questing "$CONTAINER_DIR" http://archive.ubuntu.com/ubuntu/

    # qemu with the right version 
    run-nspawn -- apt install -y \
        ./guest/qemu/qemu-system-common_10.0.2+ds-1ubuntu2_amd64.deb \
        ./guest/qemu/qemu-system-x86_10.0.2+ds-1ubuntu2_amd64.deb \
        ./guest/qemu/qemu-system-data_10.0.2+ds-1ubuntu2_all.deb \
        ./guest/qemu/qemu-utils_10.0.2+ds-1ubuntu2_amd64.deb

    # for debugging
    # run-nspawn -- apt install -y \
    #     tmux \
    #     vim \
    #     gdb \
    #     ubuntu-dbgsym-keyring \
    #     ./guest/qemu/qemu-system-x86-dbgsym_10.0.2+ds-1ubuntu2_amd64.ddeb
    # for convenient glib hash table parsing in gdb
    # run-nspawn -- sh -c 'echo "deb http://ddebs.ubuntu.com/ubuntu questing main" >> /etc/apt/sources.list'
    # run-nspawn -- apt update
    # run-nspawn -- apt install -y libglib2.0-0t64-dbgsym

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
        --shell /bin/bash \
        -G "$KVM_NAME" \
        -m \
        "$USER_NAME"
fi

# we disable numa balancing which is reasonable for hypervisors that schedule a VM inside a single NUMA node.
# "If the target workload is already bound to NUMA nodes then this feature should be disabled." - Linux Docs
# (This is only necessary for CPUs with multiple NUMA nodes on operating systems that enable balancing by default)
echo 0 | sudo tee /proc/sys/kernel/numa_balancing

if [ "$#" -gt "0" ]; then
    run-nspawn "$@"
else
    run-nspawn --user "$USER_NAME" -- bash
fi
