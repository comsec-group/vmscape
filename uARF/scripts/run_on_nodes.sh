#!/bin/bash

# Run some command on all nodes

# cmd="sudo rdmsr 0x48"
cmd="cpuid -1 -l 0x8000000a --raw"

declare -a nodes=()
# nodes+=("zen1")
nodes+=("zen2")
nodes+=("zen3")
nodes+=("zen4")
nodes+=("zen5")
nodes+=("coffee")
nodes+=("raptor")

for n in "${nodes[@]}"; do
    echo "Run on '$n'"

    # ssh $n /bin/bash << EOF
    #     cmd
    # EOF
    ssh "$n" $cmd
    if [ $? -ne 0 ]; then
        # One of the commands failes
        echo "$cmd failed on '$n'"
        exit 1
    fi

done
