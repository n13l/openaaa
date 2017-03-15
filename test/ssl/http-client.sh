#!/bin/sh
export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_PROTOCOL=aducid
export OPENAAA_HANDLER=/usr/local/bin/aducid
#openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF | grep -i 'pkcs\|SSL\|Session\|Protocol\|key\|tls\|extension\|aaa'
#openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF 
/opt/aaa/bin/openssl s_client -tlsextdebug -no_ticket -connect aaa:443 <<<EOF | grep -i 'ssl'

