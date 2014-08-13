#!/bin/bash

rm demoCA -rf
rm sign.*

mkdir -p ./demoCA/{private,newcerts}
touch ./demoCA/index.txt
echo 01 > ./demoCA/serial

openssl genrsa -3 -out ./demoCA/private/cakey.pem 2048

openssl req -new -x509 -days 36500 -key ./demoCA/private/cakey.pem -out ./demoCA/cacert.pem -subj '/C=US/ST=California/L=San Jose/O=Adobe Systems Incorporated/OU=Adobe Reader/CN=Adobe Systems Incorporated'

keytool -genkey -keyalg RSA -alias sign -keystore sign.keystore -storepass asdfgh -storetype jks -keypass asdfgh -dname 'C=CN,S=Beijing,L=Chaoyang,O=AntiRoot,OU=AntiRoot,CN=AntiRoot'

keytool -certreq -alias sign -keyalg RSA -file sign.csr -keystore sign.keystore -storepass asdfgh -keypass asdfgh

openssl ca -in sign.csr -out sign.pem  -config openssl.cnf

openssl x509 -in sign.pem -out sign.cer

keytool -import -alias ca -trustcacerts -file ./demoCA/cacert.pem -keystore sign.keystore -storepass asdfgh -keypass asdfgh
keytool -import -alias sign  -trustcacerts -file  sign.cer -keystore sign.keystore -storepass asdfgh -keypass asdfgh

rm -rf ./demoCA
rm sign.csr sign.pem sign.cer
