export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_AUTHORITY=auth.aducid.com
export OPENAAA_PROTOCOL=aaa
export OPENAAA_HANDLER=/usr/local/bin/aducid
sudo -E /opt/aaa/bin/openssl s_server -key ./test/ssl/key.pem -cert ./test/ssl/cert.pem -accept 443 -www
