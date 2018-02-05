export OPENSSL_CONF=./etc/pkcs11-linux.cfg
export OPENAAA_AUTHORITY=auth.example.com
export OPENAAA_PROTOCOL=aaa
export OPENAAA_HANDLER=/usr/local/bin/tlsbinder
export OPENAAA_VERBOSITY=4
export PATH=/opt/aaa/bin:$PATH
sudo -E /opt/aaa/bin/openssl s_server -key ./test/ssl/key.pem -cert ./test/ssl/cert.pem -accept 4443 -www
