#!/bin/bash

# Open a new file descriptor that redirects to stdout:
# For logging
exec 3>&1

BB_VER="1.31.0"

CWD=$(pwd)

# Tmp file to store initramfs structure
INITRAMFS_DIR="${CWD}/initramfs"

INITRAMFS_CPIO_GZ_FILE="initramfs.cpio.gz"

BUSYBOX_PATH="${CWD}/busybox"

INIT="/bin/sh"
GUEST_CWD="/"

function log() {
    if [ "$verbose" = true ]; then
        printf "$(date +"%H:%M:%S") $* \n" 1>&3
    fi
}

function log_err() {
    printf "$(date +"%H:%M:%S") ERROR: $* \n" >&2
}

out=$CWD
init=
guest_cwd=$GUEST_CWD
force=false
verbose=false
share=false

function usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "   -i, --init <INIT>      Init executable to run (default: $INIT)"
    echo "   -o, --out <DIR>        Path to store the initramfs.cpio.gz (default: $out)"
    echo "   -f, --force            Force recreate initramfs structure"
    echo "   -s, --share            Mount p9 share"
    echo "   -w, --cwd <DIR>        Working directory to use on the guest (default: $guest_cwd)"
    echo "   -h, --help             Display this help message."
    echo "   -v, --verbose          Display verbose output."
}

PARSED_ARGUMENTS=$(getopt --name "$0" --options=i:o:fsw:hv --longoptions init:,out:,force,share,cwd:help,verbose -- "$@")
VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" != "0" ]; then
    echo "Invalid argument"
    usage
    exit 1
fi

eval set -- "$PARSED_ARGUMENTS"
while true; do
    case "$1" in
        -i|--init)
            init=`realpath "$2"`
            shift 2
            ;;
        -o|--out)
            out="$2"
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

log "Arguments parsed"

# Get busybox
if [ ! -f $BUSYBOX_PATH ]; then
    log "Downloading busybox to $BUSYBOX_PATH"
    curl -L "https://www.busybox.net/downloads/binaries/${BB_VER}-defconfig-multiarch-musl/busybox-x86_64" > "${BUSYBOX_PATH}"
fi

if [ "$force" = true ]; then
    log "Delete $INITRAMFS_DIR if existing"
    rm -rf $INITRAMFS_DIR
fi

if [ ! -d $INITRAMFS_DIR ]; then
    # Create initramfs file structure
    log "Creating initramfs file structure at $INITRAMFS_DIR"
    mkdir -p "${INITRAMFS_DIR}"
    cd "${INITRAMFS_DIR}"
    mkdir -p bin dev etc lib mnt/host0 proc sbin sys tmp var
    cd bin
    cp "${BUSYBOX_PATH}" busybox
    chmod +x busybox
    ln -s busybox mount
    ln -s busybox sh

    if [ -n "$init" ]; then
        cp $init user_init
        chmod +x user_init
        init="exec /bin/user_init"
    else
        init="setsid cttyhack $INIT"
    fi

    cwd="cd $guest_cwd"

    mount_p9=""
    if [ "$share" = true ]; then
        mount_p9="mount -t 9p         host0       /mnt/host0  -o trans=virtio,version=9p2000.L"
    fi

    cd ..

    # Create init script
    echo "Creating init file"
    cat > init << EOF
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t devtmpfs   devtmpfs    /dev
mount -t proc       proc        /proc
mount -t sysfs      sysfs       /sys
mount -t tmpfs      tmpfs       /tmp
$mount_p9
echo "root:x:0:0:root:/root:/bin/sh" > /etc/passwd
echo "root::0:0:99999:7:::" > /etc/shadow
echo "root:x:0:" > /etc/group
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 644 /etc/group
echo "nameserver 10.0.2.3" > /etc/resolv.conf
ifconfig eth0 10.0.2.15
route add default gw 10.0.2.2
insmod /mnt/host0/uARF/kmods/pi/pi.ko
insmod /mnt/host0/uARF/kmods/rap/rap.ko
echo 512 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
$cwd
$init
EOF
    chmod +x init
fi

# Create gz compressed cpio archive
echo "Creating initramfs.cpio.gz"
cd "${INITRAMFS_DIR}"
find . | cpio -o -H newc | gzip > "${out}/${INITRAMFS_CPIO_GZ_FILE}"

cd "${CWD}"
