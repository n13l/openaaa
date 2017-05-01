#!/bin/sh
kill -HUP $(ps -A | grep aaa | sed -e 's/^[ \t]*//' | cut -d" " -f1) 2>/dev/null
