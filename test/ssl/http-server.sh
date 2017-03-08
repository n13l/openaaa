export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_AUTHORITY=http://orangebox-p3.aducid.com/AIM/services/R4
export OPENAAA_PROTOCOL=aducid
export OPENAAA_HANDLER=/usr/local/bin/aducid
openssl s_server -key ./test/ssl/key.pem -cert ./test/ssl/cert.pem -accept 44330 -www
