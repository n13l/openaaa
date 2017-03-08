#!/bin/sh
export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_PROTOCOL=aaa
export OPENAAA_HANDLER=none
#openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF | grep -i 'pkcs\|SSL\|Session\|Protocol\|key\|tls\|extension\|aaa'
#openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF 
openssl s_client -tlsextdebug -no_ticket -connect 127.0.0.1:44330 <<<EOF | grep -i 'pkcs\|SSL'

