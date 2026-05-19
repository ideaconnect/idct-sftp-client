#!/usr/bin/with-contenv bash
# linuxserver/openssh-server runs scripts in /custom-cont-init.d as root
# before the SSH daemon starts. We create /data, chown it to the tester
# user, and make it writable so the Behat suite (which hard-codes
# `/data/...` paths) can mirror the atmoz/sftp layout exactly.
set -euo pipefail

mkdir -p /data
chown tester:users /data 2>/dev/null || chown 1001:1001 /data
chmod 0755 /data
