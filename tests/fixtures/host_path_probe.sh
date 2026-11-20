#!/bin/sh
# Fixture: host path access probe (§16.4) — attempts to read host secrets.
# Inside the isolation root these files must not exist; each failure is
# expected and reported to stdout.
for f in /etc/shadow /root/.ssh/id_rsa "$HOME/.ssh/id_rsa" /var/run/docker.sock; do
  if [ -e "$f" ]; then
    echo "LEAK: $f exists"
  else
    echo "ok: $f absent"
  fi
done
