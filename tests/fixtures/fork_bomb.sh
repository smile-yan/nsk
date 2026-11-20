#!/bin/sh
# Fixture: fork bomb limited by pids limit (§16.4 Fork Bomb).
# Spawns N long-lived children until pids.max blocks further forks.
i=0
while [ "$i" -lt 100 ]; do
  sleep 100 &
  i=$((i + 1))
done
echo "all children spawned"
wait
