#!/bin/sh

# set -x

if [ "$CERTSERVERNAME" = "" ]; then
	CERTSERVERNAME="127.0.0.1"
	echo "-"
	echo "[i] Using $CERTSERVERNAME as server common name, specify it with CERTSERVERNAME env variable"
	echo "[i] e.g. CERTSERVERNAME=mydomain.com $0"
	echo "-"
fi

if [ "$CERTCLIENTNAME" = "" ]; then
	CERTCLIENTNAME="client.local"
fi

CERTVALID=3650
# -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com"
CERTCOMMON="/C=US/ST=Denial/L=Springfield/O=Dis"

openssl genrsa -out ca.key 4096
openssl req -new -x509 -days $CERTVALID -subj "$CERTCOMMON/CN=myCA" -key ca.key -out ca.pem
echo "00" > ca.srl

openssl genrsa -out server.key 4096
openssl req -new -key server.key -nodes -subj "$CERTCOMMON/CN=$CERTSERVERNAME" -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAserial ca.srl -out server.crt


openssl genrsa -out client.key 4096
openssl req -new -key client.key -nodes -subj "$CERTCOMMON/CN=$CERTCLIENTNAME" -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAserial ca.srl -out client.crt
