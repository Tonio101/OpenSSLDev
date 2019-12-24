#!/bin/bash
#Don't forget to change the config path accordingly.
wget https://www.openssl.org/source/openssl-1.1.1d.tar.gz
tar -xvf  openssl-1.1.1d.tar.gz
cd openssl-1.1.1d/
./config --prefix=$HOME/DEV/OpenSSL_Development/BUILD --openssldir=$HOME/DEV/OpenSSL_Development/BUILD -d enable-shared
make depend
make
make install

#For testing, generate a self-signed certificate:
#openssl req -newkey rsa:2048 -nodes -keyout test_self_signed_key.pem -x509 -days 365 -out test_self_signed_cert.pem

#Initiate an OpenSSL server:
#openssl s_server -accept 8443 -cert test_self_signed_cert.pem -key test_self_signed_key.pem -cipher ALL:COMPLEMENTOFALL -WWW -no_ticket -state
