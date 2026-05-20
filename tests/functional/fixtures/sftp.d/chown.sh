#!/bin/sh
# atmoz/sftp runs scripts in /etc/sftp.d/ as root before sshd starts.
# Make the volume writable by the tester user (uid 1001 per docker-compose.yml).
chown -R 1001:1001 /home/tester/data
chmod 755 /home/tester/data
