#!/bin/bash
if [ -d "$canonical/.git" ]; then
	echo "$(basename $(git remote -v | head -n1 | awk '{print $2}' | sed -e 's/\.git$//'))"
else
	echo "$(basename $canonical)" | sed -e 's/[0-9]//g' -e 's/-//g'
fi
