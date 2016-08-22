#!/bin/sh
powerpclib=$(find /usr/powerpc64-linux-gnu/lib/ld-*.so)
powerpcdir=$(dirname "$powerpclib")
printf "qemu-ppc64-static $powerpclib --library-path $powerpcdir"
