#!/bin/bash

set -u
set -e

# Open a new file descriptor that redirects to stdout:
# For logging
exec 3>&1

# This script is designed to synchronize all files inside SRC to DST. The files
# COMMON_EXCLUDE and if -a it not used BUILD_EXCLUDE are excluded. Contains also a
# daemon that watches the files returned by WATCH_FILES_CMD and triggers a sync upon
# change.

# Terminate the synchronization after time time
# Done because rsync somehow gets blocked sometimes
SYNC_TIMEOUT=10

LONGOPTS=all,daemon,force,verbose,help
OPTIONS=adfvh

function usage() {
    echo "Usage: $0 [OPTION]... CONFIG"
    echo ""
    echo "Options:"
    echo "  --all, -a      Sync all files (including build artefacts etc.)"
    echo "  --daemon, -d   Start sync daemon."
    echo "  --force, -f    Delete all files at destination that do not exist at source."
    echo "  --verbose, -v  Verbose logging."
    echo "  --help, -h     Show this help message"
    echo ""
    echo "Positional Arguments:"
    echo "  CONFIG: Path to configuration file to use."
    echo ""
    echo "Configuration:"
    echo "  Store in file and provide path as CONFIG"
    echo "  All options are required"
    echo "  Options:"
    echo "    SRC:              Source path (trailing / matters!)"
    echo "    DEST:             Destination path"
    echo "    COMMON_EXCLUDE:   List of files that are always excluded"
    echo "    BUILD_EXCLUDE:    List of files that are excluded, unless --all is used"
    echo "    WATCH:            List of files to watch"
}

function log() {
    if [ "$verbose" = true ]; then
        printf "$(date +"%H:%M:%S") $* \n" 1>&3
    fi
}

function log_err() {
    printf "$(date +"%H:%M:%S") ERROR: $* \n" >&2
}

function log_err_msg() {
    log_err $*
    notify-send -u Critical "SYNC ERROR" "$*\n"
}

# -temporarily store output to be able to check for errors
# -activate quoting/enhanced mode (e.g. by writing out “--options”)
# -pass arguments only via   -- "$@"   to separate them correctly
# -if getopt fails, it complains itself to stdout
PARSED=$(getopt --options=$OPTIONS --longoptions=$LONGOPTS --name "$0" -- "$@") || exit 2
# read getopt’s output this way to handle the quoting right:
eval set -- "$PARSED"

all=false
daemon=false
force=false
verbose=false

# Read till we see --
while true; do
    case "$1" in
        -a|--all)
            all=true
            shift
            ;;
        -d|--daemon)
            daemon=true
            shift
            ;;
        -f|--force)
            force=true
            shift
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
            echo "Invalid option \"$1\""
            usage
            exit 3
            ;;
    esac
done

# handle non-option arguments
if [[ $# -ne 1 ]]; then
    echo "CONFIG file missing"
    usage
    exit 4
fi

log "All arguments parsed"

config=$(readlink -f "$1")

if [ ! -f "$config" ]; then
    echo "Config file \"$config\" does not exist"
    exit 5
fi

log "Sourcing config \"$config\""
. $config
log "Sourced config"

# Check that there is a config option named $1 and it has a value
function check_config_option() {
    log "Checking config option $1"
    local opt_name=$1
    local opt=${!opt_name} # Convert from string to variable

    log $opt_name
    log $opt

    if [ -v "$opt" ]; then
        echo "Missing config option \"$opt_name\""
        exit 5
    else
        log "Config option $opt_name exists and has value:\n$opt"
    fi
}

check_config_option SRC
check_config_option DST
# check_config_option EXCLUDE_BASE
# check_config_option EXCLUDE_EXTENDED
check_config_option WATCH

# Composes the rsync command, based on the cli arguments
# Use nameref
function get_rsync_args() {
    log "Composing sync command"
    local -n args=$1
    args=("--info=NAME" "-a" "--no-links")

    if [ -n "$EXCLUDE_BASE" ]; then
        log "Adding base exclude"
        IFS=" " read -r -a exclude <<< "$EXCLUDE_BASE"
        for e in "${exclude[@]}"; do
            args+=("--exclude=$e")
        done
    fi

    if [ "$all" = false ]; then
        log "Exclude EXCLUDE_EXTENDED"
        if [ -n "$EXCLUDE_EXTENDED" ]; then
            IFS=" " read -r -a exclude <<< "$EXCLUDE_EXTENDED"
            for e in "${exclude[@]}"; do
                args+=("--exclude=$e")
            done
        fi
    fi

    if [ "$force" = true ]; then
        log "Force enabled"
        args+=("--delete")
    fi

    args+=("$SRC")
    args+=("$DST")
}

declare -a rsync_args
get_rsync_args rsync_args

log "rsync args:" `declare -p rsync_args`

if [ "$daemon" = true ]; then
    # TODO: should be update this list inside loop?
    if [ -z "$WATCH" ]; then
        echo "Cannot start daemon without watching files"
        exit 6
    fi
    log "Watching files: \n$WATCH"
    log "Running upon event: rsync ${rsync_args[@]}"

    while true; do
        echo "==================="
        log "Start sync"
        timeout $SYNC_TIMEOUT rsync "${rsync_args[@]}"

        retVal=$?

        if [ $retVal -eq 124 ]; then
            log_err_msg "Timeout triggered ($SYNC_TIMEOUT seconds)! Retry..."
            continue
        fi

        if [ $? -eq 125 ]; then
            log_err_msg "timeout utility failed, exit"
            exit $?
        fi

        if [ $retVal -eq 125 ]; then
            log_err_msg "timeout utility failed, exit"
            exit $?
        fi

        if [ $retVal -ne 0 ]; then
            log_err_msg "Rsync Error Encountered: $retVal, exit"
            exit $?
        fi

        log "Sync done. Block for new event"
        notify-send -t 200 DONE

        # Wait for event to happen
        # Editors may not modify, but "replace" the file => monitor other events too
        inotifywait -e modify -e delete_self -e move_self $WATCH

        if [ $? -ne 0 ]; then
            log_err_msg "inotifywait failed, exit"
            exit $?
        fi
    done
else
    log "Running: rsync ${rsync_args[@]}"
    rsync "${rsync_args[@]}"
fi
