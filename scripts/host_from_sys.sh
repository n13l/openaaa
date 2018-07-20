#!/bin/sh
set -e
opt=$(echo "$*" | tr '[:upper:]' '[:lower:]')
printf "OPT: $opt"
for arg in $opt ; do
	case $arg in
	*arm-none-eabilinux*) printf "linux\n"; ;;
	*mingw*)  printf "win32\n"; ;;
	*cygwin*) printf "win32\n"; ;;
	*cygnus*) printf "win32\n"; ;;
	*linux*)  printf "linux\n"; ;;
	*darwin*) printf "darwin\n"; ;;
	*390)     printf "os390\n"; ;;
	*aix)     printf "aix\n"; ;;
	*)
	esac
done
