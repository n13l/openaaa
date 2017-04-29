#!/bin/sh
kill -TERM $(ps -A | grep aaa | sed -e 's/^[ \t]*//' | cut -d" " -f1)
