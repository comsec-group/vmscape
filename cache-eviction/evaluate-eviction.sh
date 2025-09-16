#!/bin/env bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
ATTACK_DIR="$SCRIPT_DIR/../vmscape/attack"
GUEST_DIR="$SCRIPT_DIR/../vmscape/guest"
RUN_VM="$GUEST_DIR/run-vm.sh"

INITRD_SCRIPT="$GUEST_DIR/gen_initramfs.sh"
INITRD_FILE="$SCRIPT_DIR/initramfs-evict.cpio.gz"

march=MARCH_ZEN4

PARSED_ARGUMENTS=$(getopt --name "$0" --options= --longoptions zen5 -- "$@")
VALID_ARGUMENTS=$?
if [ "$VALID_ARGUMENTS" != "0" ]; then
    echo "Invalid argument"
    usage
    exit 1
fi

eval set -- "$PARSED_ARGUMENTS"
while [ "$#" -gt 1 ]; do
    case "$1" in
        --zen5)
            march=MARCH_ZEN5
            shift
            ;;
        *)
            # We check for invalid options before. So this should not happen
            echo "Should not be executed ($0)"
            exit 2
            ;;
    esac
done

if ! [ -f "$INITRD_FILE" ]; then
    pushd "$GUEST_DIR"
    echo "# Create eviction initramfs"
    bash "$INITRD_SCRIPT" --share --cwd "/mnt/" --out "$INITRD_FILE" --force --init "$SCRIPT_DIR/init-evict.sh"
    popd
fi

make -C "$SCRIPT_DIR" "MARCH=$march"
cp "$SCRIPT_DIR/evict_eval" "$ATTACK_DIR"

mkdir -p "$SCRIPT_DIR/data"

# inside VM
for i in {1..1000}; do
    bash "$RUN_VM" --initramfs "$INITRD_FILE" | tee "$SCRIPT_DIR/data/run-evict-vm-$i.out"
    sleep 5
done

# outside VM
for i in {1..1000}; do
    "$SCRIPT_DIR/evict_eval" | tee "$SCRIPT_DIR/data/run-evict-native-$i.out"
    sleep 5
done

