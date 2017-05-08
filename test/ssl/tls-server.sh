export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_AUTHORITY=orange-d1.aducid.com
export OPENAAA_PROTOCOL=aaa
export OPENAAA_HANDLER=/usr/local/bin/aducid
export OPENAAA_VERBOSITY=4
export OPENAAA_SERVICE=127.0.0.1
export PATH=/opt/aaa/bin:$PATH
sudo -E /opt/aaa/bin/openssl s_server -key ./test/ssl/key.pem -cert ./test/ssl/cert.pem -accept 4443 -www
