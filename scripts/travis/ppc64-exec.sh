#!/bin/sh
powerpclib=$(find /usr/powerpc64-linux-gnu/lib/ld-*.so)
powerpcdir=$(dirname "$powerpclib")
# gdb gdb_core core
# (gdb) set arm abi
qemu-powerpc64-static $powerpclib --library-path $powerpcdir $1
