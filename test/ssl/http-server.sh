export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_AUTHORITY=http://www.example.com
export OPENAAA_PROTOCOL=aaa
export OPENAAA_HANDLER=/usr/local/bin/aducid
openssl s_server -key ./test/ssl/key.pem -cert ./test/ssl/cert.pem -accept 44330 -www
