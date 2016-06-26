#!/bin/sh
s390lib=$(find /usr/s390x-linux-gnu/lib/ld-*.so)
s390dir=$(dirname "$s390lib")
printf "qemu-s390x-static $s390lib --library-path $s390dir"
