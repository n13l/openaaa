#!/bin/sh
export BUILD_MAJOR=0
export BUILD_MINOR=0
export BUILD_REVISION=1

num=`echo $1 | cut -d. -f1`
if [ $num = *[[:digit:]]* ]; then export BUILD_MAJOR=$num ; fi
num=`echo $1 | cut -d. -f2`
if [ $num = *[[:digit:]]* ]; then export BUILD_MINOR=$num ; fi
num=`echo $1 | cut -d. -f3`
if [ $num = *[[:digit:]]* ]; then export BUILD_REVISION=$num ; fi
echo "release: $BUILD_MAJOR $BUILD_MINOR $BUILD_REVISION"
