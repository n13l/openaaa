#!/bin/sh
export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_PROTOCOL=aaa
export OPENAAA_HANDLER=/usr/local/bin/aducid
nghttp -vvvv https://aaa.rtfm.cz

