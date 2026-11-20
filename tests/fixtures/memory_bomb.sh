#!/bin/sh
# Fixture: memory bomb (§16.4 Memory Bomb) — unbounded variable growth.
x=a
while :; do
  x="$x$x"
done
