#!/bin/sh
export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_PROTOCOL=aaa
export OPENAAA_HANDLER=/usr/local/bin/tlsbinder
export OPENAAA_VERBOSE=4
openssl s_client -connect localhost:4443

