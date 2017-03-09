#!/bin/bash
if [ -d ".git" ]; then
	echo "$(basename $(git remote -v | head -n1 | awk '{print $2}' | sed -e 's/\.git$//'))"
else
	echo "openaaa" | sed -e 's/[0-9]//g' -e 's/-//g'
fi
