#!/bin/sh
export OPENSSL_CONF=./etc/pkcs11-linux.cfg
#openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF | grep -i 'pkcs\|SSL\|Session\|Protocol\|key\|tls\|extension\|aaa'
#openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF 
openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF | grep -i 'pkcs\|SSL'

