#!/bin/sh
# Fixture: open-file bomb (§16.4) — exhaust RLIMIT_NOFILE.
n=0
while :; do
  exec 9<$0 || exit 97
  n=$((n + 1))
done
echo "opened $n"
