#!/bin/env bash
set -e
set -u

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
DATA_DIR="$SCRIPT_DIR/data"

mkdir -p "$DATA_DIR"

for i in {1..100}; do
    echo "# RUN NUMBER $i"

    bash "$SCRIPT_DIR/guest/run-vm.sh" --eval \
        | tee "$DATA_DIR/run-eval-$i-break.out"
    
    cp "$SCRIPT_DIR/attack/secret.txt" "$DATA_DIR/run-eval-$i-attack-secret.txt"
    cp "$SCRIPT_DIR/guest/secret.txt"  "$DATA_DIR/run-eval-$i-guest-secret.txt"
done

echo "# Evaluation completed!"