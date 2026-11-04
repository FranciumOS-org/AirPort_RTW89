#!/bin/bash
# awdl_watch.sh - 60 s of what crosses awdl0, then the driver's log, with no
# debugger attached. Have the other device's AirDrop share sheet open.
#
#   sudo tools/awdl_watch.sh > awdl-watch.txt 2>&1
set -u
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"

# -p: no promiscuous mode. Turning it on is a change to awdl0 that the test does not need.
/usr/sbin/tcpdump -p -i awdl0 -n -l -tttt not port 5353 &
dump_pid=$!
sleep 60
kill "$dump_pid" 2>/dev/null
wait "$dump_pid" 2>/dev/null
echo "=== driver log"
"$here/../build/out/rtw89ctl" log 2>&1 | grep -E 'awdl|TLV' | tail -n 400
