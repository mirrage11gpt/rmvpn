#!/usr/bin/env bash
set -euo pipefail

out=${1:-pki}
umask 077
mkdir -p "$out/offline" "$out/online" "$out/certs"

openssl genpkey -algorithm ED25519 -out "$out/offline/root-ca.key"
openssl req -x509 -new -key "$out/offline/root-ca.key" -days 3650 -subj "/CN=RiseVPN Offline Root CA" -out "$out/certs/root-ca.pem"
openssl genpkey -algorithm ED25519 -aes-256-cbc -out "$out/online/intermediate-ca.key.enc"
openssl req -new -key "$out/online/intermediate-ca.key.enc" -subj "/CN=RiseVPN Node Intermediate CA" -out "$out/online/intermediate-ca.csr"
openssl x509 -req -in "$out/online/intermediate-ca.csr" -CA "$out/certs/root-ca.pem" -CAkey "$out/offline/root-ca.key" -CAcreateserial -days 730 -extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n') -out "$out/certs/intermediate-ca.pem"
chmod 0600 "$out"/offline/* "$out"/online/*
printf 'Root CA created in %s/offline. Move it offline before production.\n' "$out"
