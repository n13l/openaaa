#!/bin/sh
kill -HUP $(ps -A | grep aaa | sed -e 's/^[ \t]*//' | cut -d" " -f1)
