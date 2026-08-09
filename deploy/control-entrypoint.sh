#!/bin/sh
set -eu
umask 077
# The container may restart without being recreated. Remove only the ephemeral
# decrypted copies first: after the previous start they belong to risevpn with
# mode 0600, which OpenSSL cannot truncate when container capabilities are
# restricted.
rm -f /tmp/node-ca.pem /tmp/node-ca.key
cp /run/secrets/node_ca.pem /tmp/node-ca.pem
openssl pkey -in /run/secrets/node_ca_key_encrypted -passin file:/run/secrets/node_ca_key_password -out /tmp/node-ca.key
chown risevpn:risevpn /tmp/node-ca.pem /tmp/node-ca.key
chmod 0600 /tmp/node-ca.pem /tmp/node-ca.key
exec su-exec risevpn /usr/local/bin/risevpn-control
