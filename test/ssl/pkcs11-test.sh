#!/bin/sh
export OPENSSL_CONF=./etc/pkcs11-linux.cfg
openssl engine pkcs11 -t
