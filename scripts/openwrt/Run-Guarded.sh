#!/bin/bash
set -u
setsid "$@" &
build_pid=$!
(
  while kill -0 "$build_pid" 2>/dev/null; do
    disk_kb=$(df -Pk . | awk 'NR==2 {print $4}')
    memory_kb=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
    if (( disk_kb < 650000 || memory_kb < 500000 )); then
      printf 'RESOURCE GUARD: disk=%s KiB, memory=%s KiB; stopping build group.\n' "$disk_kb" "$memory_kb" >&2
      kill -TERM -- "-$build_pid" 2>/dev/null || true
      exit
    fi
    sleep 10
  done
) &
guard_pid=$!
wait "$build_pid"
result=$?
kill "$guard_pid" 2>/dev/null || true
wait "$guard_pid" 2>/dev/null || true
exit "$result"
