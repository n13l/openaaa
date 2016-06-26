#!/bin/sh
armlib=$(find /usr/arm-linux-gnueabi/ -type f -exec test -x {} \; -print | grep ld)
armlib="/usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3"
armdir=$(dirname "$armlib")
qemu-arm-static $armlib --library-path $armdir $1
