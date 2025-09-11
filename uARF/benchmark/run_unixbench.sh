#!/bin/bash

DRIVE_PATH="$HOME/benchmark_drive"
DRIVE_IMG="$DRIVE_PATH/bookworm.img"
DRIVE_RSA_PUB="$DRIVE_PATH/bookworm_misc/bookworm.id_rsa"

ssh -i $DRIVE_RSA_PUB -p 10021 -o "StrictHostKeyChecking no" root@localhost /bin/bash << EOF
    mount -t 9p host0 /mnt/host0 -o trans=virtio,version=9p2000.L;
    cd /mnt/host0/unixbench/UnixBench/;
    make clean;
    make
    ./Run
EOF
if [ $? -ne 0 ]; then
    echo "One of the commands failed"
fi
