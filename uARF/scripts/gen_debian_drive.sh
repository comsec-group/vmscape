#!/usr/bin/env bash

# 2025 Based on create-image.sh by the syskaller project, adapted for our purpose.
# Copyright 2016-2025 syzkaller project authors. All rights reserved.

# Crates user `root` with empty password
# Start qemu:
# qemu-system-x86_64 \
#     -m 2G \
#     -kernel ../benchmark/bzImage \
#     -append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
#     -drive file=./debian_out/bookworm.img,format=raw \
#     -net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
#     -net nic,model=e1000 \
#     -enable-kvm \
#     -nographic \
#     -virtfs local,path=`pwd`,mount_tag=host0,security_model=mapped

# Connect via ssh using `ssh -i $IMAGE/bullseye.id_rsa -p 10021 -o "StrictHostKeyChecking no" root@localhost`

set -e
set -u

exec 3>&1

#RELEASE="bullseye"
RELEASE="bookworm"

CWD=$(pwd)

DRIVE_RAW="${RELEASE}_raw"
DRIVE_CONF="${RELEASE}_conf"
DRIVE_MISC="${RELEASE}_misc"
DRIVE_IMG="$RELEASE.img"

INSTALL_PKGS="make,git,vim,gcc,openssh-server,curl,tar,gcc,libc-devtools,time,sudo,less,psmisc,debian-ports-archive-keyring,libc6-dev"

# INSTALL_PKGS=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,selinux-utils,policycoreutils,checkpolicy,selinux-policy-default,firmware-atheros,debian-ports-archive-keyring

SEEK=2047 # Size of disk in MB -1
DEBARCH=amd64

out=$CWD
guest_cwd="/"
verbose=true
force=false

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
    echo "   -o, --out <DIR>        Path to store img and artefacts (default: $out)"
    echo "   -f, --force            Force recreate drive structure"
    echo "   -s, --share            Mount p9 share"
    # echo "   -w, --cwd <DIR>        Working directory to use on the guest (default: $guest_cwd)"
    echo "   -h, --help             Display this help message."
    echo "   -v, --verbose          Display verbose output."
    echo ""
}

PARSED_ARGUMENTS=$(getopt --name "$0" --options=o:fsw:vh --longoptions out:,force,share,cwd:verbose,help -- "$@")
VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" != "0" ]; then
    echo "Invalid argument"
    usage
    exit 1
fi

eval set -- "$PARSED_ARGUMENTS"
while true; do
    case $1 in
        -o|--out)
            out=$(readlink -f "$2")
            shift 2
            ;;
        -f|--force)
            force=true
            shift
            ;;
        -s|--share)
            share=true
            shift
            ;;
        -w|--cwd)
            guest_cwd="$2"
            shift 2
            ;;
        -v|--verbose)
            verbose=true
            # set -x
            shift
            ;;
        -h|--help)
            usage
            exit 1
            ;;
        --)
            shift
            break;
            ;;
        *)
            # We check for invalid options before. So this should not happen
            echo "Should not be executed"
            exit 2
            ;;
    esac
done

log_debug "Arguments parsed"

mkdir -p "$out"
drive_raw="$out/$DRIVE_RAW"
drive_conf="$out/$DRIVE_CONF"
drive_misc="$out/$DRIVE_MISC"
drive_img="$out/$DRIVE_IMG"

log_info "Generator output: \n\t raw:\t\t $drive_raw\n\t configured:\t\t $drive_conf\n\t misc:\t\t $drive_misc\n\timage:\t\t $drive_img"

# Raw
if [ -a "$drive_raw" ] && [ "$force" = true ]; then
    log_info "Raw drive '$drive_raw' already exist. Removing"
    sudo rm -r "$drive_raw"
    sudo rm -r "$drive_conf"
    sudo rm -r "$drive_img"
fi

if [ ! -d "$drive_raw" ]; then
    log_info "Debootstrapping to '$drive_raw'"

    sudo mkdir -p "$drive_raw"
    sudo chmod 0755 "$drive_raw"

    debootstrap_params="--arch=$DEBARCH --include=$INSTALL_PKGS --components=main,contrib,non-free,non-free-firmware $RELEASE $drive_raw"
    sudo --preserve-env=http_proxy,https_proxy,ftp_proxy,no_proxy debootstrap $debootstrap_params
else
    log_info "Raw drive '$drive_raw' already exists. Skip"
fi

# Configure
if [ -a "$drive_conf" ] && [ "$force" = true ]; then
    log_info "Configured drive '$drive_conf' already exists. Removing"
    sudo rm -r "$drive_conf"
    sudo rm -r "$drive_img"
fi

if [ ! -d "$drive_conf" ]; then
    log_info "Configuring drive '$drive_conf'"
    sudo cp -r "$drive_raw" "$drive_conf"

    # Set some defaults and enable promtless ssh to the machine for root.
    sudo sed -i '/^root/ { s/:x:/::/ }' "$drive_conf/etc/passwd"

    echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a "$drive_conf/etc/inittab"

    # Login as root with empty password
    # echo 'T0:23:respawn:/sbin/getty -L -a root ttyS0 115200 vt100' | sudo tee -a "$drive_conf/etc/inittab"
    # echo 'T0:23:respawn:/sbin/getty -a root -L ttyS0 115200 vt100' | sudo tee -a "$drive_conf/etc/inittab"

    # Fstab
    echo '/dev/root / ext4 defaults 0 0' | sudo tee -a "$drive_conf/etc/fstab"
    # echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $drive_dir_path/etc/fstab
    # echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $drive_dir_path/etc/fstab
    # echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $drive_dir_path/etc/fstab
    # echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $drive_dir_path/etc/fstab
    if [ "$share" = true ]; then
        sudo mkdir -p "$drive_conf/mnt/host0"
        echo "mount -t 9p host0 /mnt/host0 -o trans=virtio,version=9p2000.L" | sudo tee -a "$drive_conf/etc/fstab"
    fi

    # Networking
    printf '\nauto eth0\niface eth0 inet dhcp\n' | sudo tee -a "$drive_conf/etc/network/interfaces"
    echo -en "127.0.0.1\tlocalhost\n" | sudo tee "$drive_conf/etc/hosts"
    echo "nameserver 8.8.8.8" | sudo tee -a "$drive_conf/etc/resolv.conf"
    echo "uarf" | sudo tee "$drive_conf/etc/hostname"

    # SSH
    if [ -a "$drive_misc/$RELEASE.id_rsa" ] && [ "$force" = true ]; then
        log_info "SSH key '$drive_misc/$RELEASE.id_rsa' already exists. Removing"
        rm "$drive_misc/$RELEASE.id_rsa"
        rm "$drive_misc/$RELEASE.id_rsa.pub"
    fi

    mkdir -p "$drive_misc"

    if [ ! -f "$drive_misc/$RELEASE.id_rsa" ]; then
        ssh-keygen -f "$drive_misc/$RELEASE.id_rsa" -t rsa -N ''
    fi

    sudo mkdir -p "$drive_conf/root/.ssh/"
    cat "$drive_misc/$RELEASE.id_rsa.pub" | sudo tee "$drive_conf/root/.ssh/authorized_keys"
else
    log_info "Configured drive '$drive_conf' already exists. Skip"
fi

# Image
if [ -a "$drive_img" ] && [ "$force" = true ]; then
    log_info "Image '$drive_img' already exists. Removing"
    sudo rm "$drive_img"
fi

if [ ! -f "$drive_img" ]; then
    log_info "Creating image '$drive_img'"

    dd if=/dev/zero of="$drive_img" bs=1M seek=$SEEK count=1
    sudo mkfs.ext4 -F "$drive_img"
    sudo mkdir -p "/mnt/$RELEASE"
    sudo mount -o loop "$drive_img" "/mnt/$RELEASE"
    sudo cp -a "$drive_conf/." "/mnt/$RELEASE/."
    sudo umount "/mnt/$RELEASE"
else
    log_info "Drive image '$drive_img' already exists. Skip"
fi
