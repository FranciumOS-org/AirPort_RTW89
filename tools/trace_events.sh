#!/bin/bash
# trace_events.sh - attach to the running wifip2pd for 45 s and report which
# events reach IO80211's _writeEventBuffer, what the action frames carry and
# whether wifip2pd's callback and parser see them. Needs csr task_for_pid, as
# trace_wifip2pd.sh does. wifip2pd is stopped briefly at each event. Its AWDL
# log, debug level included, goes to trace-events-log.txt beside this repo's top.
#
#   sudo tools/trace_events.sh > trace-events.txt
set -u
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"
pid="$(pgrep -x wifip2pd)" || { echo "wifip2pd is not running" >&2; exit 1; }
logfile="$here/../trace-events-log.txt"

/usr/bin/log stream --level debug --style compact \
    --predicate 'process == "wifip2pd" AND subsystem BEGINSWITH "com.apple.awdl"' > "$logfile" &
log_pid=$!

# The run ends in trace_events.py, at the first event after 45 s. Never signal
# wifip2pd to stop it: it shuts down on SIGINT, and until a relaunch can get
# awdl0 back that costs a restart.
/usr/bin/lldb -b -p "$pid" -k 'process detach' \
    -o "command script import $here/trace_events.py" \
    -o 'script trace_events.setup(lldb.debugger)' \
    -o 'breakpoint set -n _writeEventBuffer -s IO80211' \
    -o 'breakpoint command add -F trace_events.on_event 4' \
    -o 'continue' \
    -o 'process detach' < /dev/null &
lldb_pid=$!
# No events at all: give up on lldb alone, which detaches as it goes.
( sleep 60; kill "$lldb_pid" 2>/dev/null ) &
watchdog=$!
wait "$lldb_pid"
kill "$watchdog" 2>/dev/null
kill "$log_pid" 2>/dev/null
chmod 644 "$logfile"
