#!/bin/sh
kill -KILL $(ps -A | grep aaa | sed -e 's/^[ \t]*//' | cut -d" " -f1)
