#!/bin/sh
if [ -d .git ]; then
	echo "$(basename $(git remote -v | head -n1 | awk '{print $2}' | sed -e 's/\.git$//'))"
else
	echo "$(basename $PWD)"
fi
