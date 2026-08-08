#!/bin/sh
set -eu
umask 077
cp /run/secrets/node_ca.pem /tmp/node-ca.pem
openssl pkey -in /run/secrets/node_ca_key_encrypted -passin file:/run/secrets/node_ca_key_password -out /tmp/node-ca.key
chown risevpn:risevpn /tmp/node-ca.pem /tmp/node-ca.key
chmod 0600 /tmp/node-ca.pem /tmp/node-ca.key
exec su-exec risevpn /usr/local/bin/risevpn-control
