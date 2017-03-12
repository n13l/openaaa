make DEBUG=1 && sudo make modules_install && source ./test/ssl/http-client2.sh <<<EOF | grep -i 'pkcs\|SSL'
