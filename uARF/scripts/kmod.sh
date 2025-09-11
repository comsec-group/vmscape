#!/bin/bash

# Reload the kernel module provided as an argument.
# It is assumed that the kernel module resides at KMOD_BASE/$1/$1.ko

set -e

UARF_PATH="${UARF_PATH:-$HOME/uARF}"

# Enable only after reading potential globals
set -u

CWD=$(pwd)

function usage() {
    echo "Usage: $0 [OPTIONS] <MODULE_NAME>"
    echo ""
    echo "Options"
    echo "  -r, --recompile     Recompile modules."
    echo "  -t, --tmp           Copy module to /tmp and load from there."
    echo "  -h, --help          Display this help message."
    echo "  -v, --verbose       Show verbose output."
    echo ""
    echo "Global Variables"
    echo "  UARF_PATH           Path to uARF repo (current: $UARF_PATH)"
    echo ""
}

function log() {
    if [ "$verbose" = true ]; then
        printf "$(date +"%H:%M:%S") $* \n"
    fi
}

function log_err() {
    printf "$(date +"%H:%M:%S") ERROR: $* \n" >&2
}

recompile=false
use_tmp=false
verbose=false
declare -a module_names=()

while [ "$#" -gt 0 ]; do
    case $1 in 
        -h|--help)
            usage
            exit
            ;;
        -r|--recompile)
            recompile=true
            shift
            ;;
        -t|--tmp)
            use_tmp=true
            shift
            ;;
        -v|--verbose)
            verbose=true
            shift
            ;;
        -*)
            log_err "Unknown option \"$1\""
            usage
            exit 1
            ;;
        *)
            module_names+=($1)
            shift
    esac
done

if [ "${#module_names[@]}" -eq 0 ]; then
    log_err "No kernel module specified"
    usage
    exit 1
fi

# Reloads the kernel moduel, whose name is passed as the argument
function reload_module() {
    module_names=$1
    module_file=$module_names.ko
    module_path=$(find "$UARF_PATH" -name $module_file -exec realpath {} \;)

    if [ -z "$module_path" ]; then
        echo "No file named $module_file found in $UARF_PATH"
        exit 1
    fi

    log "Reloading $module_names"

    if [ "$use_tmp" = true ]; then
        log "Copy module from $module_file to /tmp/$module_file"
        cp "$module_path" /tmp
        module_path="/tmp/$module_file"
    fi

    if lsmod | grep -qE "^$module_names\s+"; then
        log "Module '$module_names' is loaded. Reloading..."
        sudo rmmod $module_names
        out=$?
        if [ $out -ne 0 ]; then
            log_err "Removing module"
            exit 1
        fi
    else
        log "Module '$module_names' is not loaded. Loading..."
    fi

    sudo insmod $module_path
    out=$?
    if [ $out -ne 0 ]; then
        log_err "Inserting module"
        exit 1
    fi

    if lsmod | grep -qE "^$module_names\s+"; then
        echo "Module $module_names has been (re)loaded"
    else
        log_err "ERROR: FAILED TO (RE)LOAD MODULE $module_names"
        exit 1
    fi
}

if [ "$recompile" = true ]; then
    log "Recompiling modules"
    cd $UARF_PATH
    make kmods
    cd $CWD
fi

for e in "${module_names[@]}"; do
    reload_module $e
done
