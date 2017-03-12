#!/bin/sh
export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_PROTOCOL=aducid
export OPENAAA_HANDLER=/usr/local/bin/aducid
#openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF | grep -i 'pkcs\|SSL\|Session\|Protocol\|key\|tls\|extension\|aaa'
#openssl s_client -tlsextdebug -no_ticket -connect www.cyberciti.biz:443 <<<EOF 
<<<<<<< HEAD
openssl s_client -tlsextdebug -no_ticket -connect 127.0.0.1:443 <<<EOF | grep -i 'pkcs\|SSL'
=======
openssl s_client -tlsextdebug -no_ticket -connect aaa:443 <<<EOF | grep -i 'pkcs\|SSL'
>>>>>>> 0d144b98c8458e6f09b6d61eecab9212da081dfa

