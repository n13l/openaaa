#!/bin/sh
package_dir=$(dirname $(dirname $(dirname $(readlink -f $0))))
if [ -d "$package_dir/.git" ]; then
	echo "$(basename $(git remote -v | head -n1 | awk '{print $2}' | sed -e 's/\.git$//'))"
else
	echo "$(basename $package_dir)"
fi
