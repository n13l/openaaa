#!/bin/bash
set -e
#git submodule update --init --recursive --remote
N_CPU=$(grep ^processor /proc/cpuinfo | wc -l)

CROSS_COMPILER=${CROSS_COMPILER:-gcc}
AS=${CROSS_COMPILE}as
LD=${CROSS_COMPILE}ld
CC=${CROSS_COMPILE}${CROSS_COMPILER}
CPP="$CC -E"
AR=${CROSS_COMPILE}ar
NM=${CROSS_COMPILE}nm
STRIP=${CROSS_COMPILE}strip
OBJCOPY=${CROSS_COMPILE}objcopy
OBJDUMP=${CROSS_COMPILE}objdump
MEKDEPPROG=${CROSS_COMPILE}gcc
RUNLIB=${CROSS_COMPILE}runlib

HOST_ARCH=$(uname -m)
TARGET=$(${CC:-gcc} -dumpmachine 2>&1)
TARGET_ARCH=$(echo $TARGET | sed -e s/i.86.*/i386/ -e s/x86_64.*/x86_64/ \
	-e s/.390.*/s390/ -e s/powerpc64.*/powerpc/ \
	-e s/arm-none.*/arm/ -e s/aarch64.*/arm64/ -e s/arm.*/arm32/)

PROCESSOR=$(echo $TARGET_ARCH | sed -e s/arm32/ARM/)

if [ "$HOST_ARCH" != "$TARGET_ARCH" ] ; then
	echo "cross compile for arch: $TARGET_ARCH cpu: $PROCESSOR" 
fi
if [ "$TARGET_ARCH" == "arm32" ] ; then
	export host_opt="--host=arm-linux"
fi
	
mkdir -p opt
INSTALL_DIR=$(cd opt && pwd)
(
)
