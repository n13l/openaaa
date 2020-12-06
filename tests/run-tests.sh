#!/usr/bin/env bash
export UCAP_LOG_CAPS=0
export UCAP_LOG_VERBOSE=4
script_dir=$(dirname ${BASH_SOURCE[0]})
export PATH=$script_dir/../vendor/bats-core/bin:$script_dir/../vendor/bats-core/libexec:$PATH
set -eEu -o pipefail
$script_dir/001-AAA.bats "$@"
