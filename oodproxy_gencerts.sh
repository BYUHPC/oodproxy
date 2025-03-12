#!/bin/bash

# This script is launched in the correct working directory by the spank plugin

DAYS=365

if [ "$1" = "destroy" ]
then
    rm -f -- *.key *.crt *.csr *.srl
    exit 0
elif [ "$1" != "create" ]
then
    echo "Usage: $0 <create|destroy>"
    exit 1
fi

if [[ -z "$OODPROXY_DIR" ]]
then
	echo "\$OODPROXY_DIR was empty. Aborting."
	exit 1
fi

if [[ -z "$SLURM_JOB_UID" ]]
then
	echo "\$SLURM_JOB_UID was empty. Aborting."
	exit 1
fi

if [[ -z "$SLURM_JOB_UID" || -z "$SLURM_JOB_GID" ]]
then
	echo "\$SLURM_JOB_GID was empty. Aborting."
	exit 1
fi

exec 1>/dev/null
exec 2>/dev/null

# I have no strong opinion on what the CN should be. $SLURM_JOB_ID would make sense except that it is
# technically leaking information.  It would basically tell anyone who connects to that port what job
# that process is in.  squeue, et al. already reveal the information about the host (assuming that
# the Slurm privacy settings allow that.  But is that really any worse than, say, a web server at
# example.com doing the same thing with its TLS cert (which it must do)?  We don't use the CN for
# anything and we're doing mutual TLS auth anyway, so :shrug:
uuid=$(uuidgen)

openssl genrsa -out "ca.key" 4096
openssl req -x509 -new -nodes -key "ca.key" -sha256 -days $DAYS -out "ca.crt" -subj "/CN=$uuid.ca"

for certtype in client server
do
        openssl genrsa -out "$certtype.key" 2048
        openssl req -new -key "$certtype.key" -out "$certtype.csr" -subj "/CN=$uuid"
        openssl x509 -req -in "$certtype.csr" -CA "ca.crt" -CAkey "ca.key" -CAcreateserial -out "$certtype.crt" -days $DAYS -sha256
	rm -f -- "$certtype.csr"
done

cat "ca.crt" "client.crt" > "ca+client.crt"


# After creating these files, we need to copy them to a location that the user can access them from, a temporary directory specified by $OODPROXY_DIR
chmod 700 "$OODPROXY_DIR"
cp -p server.key {ca,client,server}.crt ca+client.crt "$OODPROXY_DIR/"
chown -R "$SLURM_JOB_UID:$SLURM_JOB_GID" "$OODPROXY_DIR"
