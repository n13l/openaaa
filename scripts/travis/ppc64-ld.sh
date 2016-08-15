#!/bin/sh
powerpclib=$(find /usr/powerpc64-linux-gnu/lib/ld-*.so)
powerpcdir=$(dirname "$powerpclib")
printf "qemu-powerpc64-static $powerpclib --library-path $powerpcdir"
