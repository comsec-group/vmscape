#!/bin/bash

set -e
set -u

echo "\$ hostname"
hostname

echo "\$ cat /proc/cmdline"
cat /proc/cmdline

echo "\$ name -a"
uname -a

echo "\$ cat /etc/lsb-release"
cat /etc/lsb-release

echo "\$ cat /proc/cpuinfo | grep 'microcode' | head -n 1"
cat /proc/cpuinfo | grep "microcode" | head -n 1
