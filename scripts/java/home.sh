#!/bin/sh
if [ ! -z "$JDK_HOME" ]; then 
	echo "$JDK_HOME"
	exit 0; 
fi

if [[ "$1" == "linux" ]]; then 
	export JDK_HOME=$(readlink -f `which javac` | sed "s:/bin/javac::")
	echo "$JDK_HOME"; exit 0;
fi

if [[ "$1" == "darwin" ]]; then
	export JDK_HOME=$( $(dirname $(readlink $(which javac)))/java_home )
	echo "$JDK_HOME"; exit 0;
fi

if [[ "$1" == "win32" ]]; then
	export JDK_HOME=$(dirname $(dirname $(which javac)))
	echo "$JDK_HOME"; exit 0;
fi
