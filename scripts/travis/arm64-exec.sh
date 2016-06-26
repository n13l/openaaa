#!/bin/sh
armlib=$(find /usr/aarch64-linux-gnu/ -type f -exec test -x {} \; -print | grep ld)
armlib="/usr/aarch64-linux-gnu/lib/ld-linux-aarch64.so.1"
armdir=$(dirname "$armlib")
qemu-aarch64-static $armlib --library-path $armdir $1
