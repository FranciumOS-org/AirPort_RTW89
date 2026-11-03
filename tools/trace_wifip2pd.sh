#!/bin/bash
# trace_wifip2pd.sh - find the Apple80211 call that makes wifip2pd's
# AWDLInterface init fail with <Apple80211Error Invalid Parameters> (-3900).
#
# WHY LLDB AND NOT DTRACE: the DTrace pid provider needs
# CSR_ALLOW_UNRESTRICTED_DTRACE and attaching to wifip2pd - which is sandboxed,
# unlike WindowServer - needs CSR_ALLOW_TASK_FOR_PID. Both are in
# csr-active-config 0xA67; set it with RembrandtGPU's
# `sudo tools/efi.sh csr add task_for_pid dtrace` and reboot. `csrutil status`
# shows Debugging and DTrace Restrictions disabled once it is in.
#
# WHY IT ATTACHES AT LAUNCH: wifip2pd creates the AWDL interface when it
# starts, and once that has failed it does not try again on its own - a window
# of attached time on the running daemon catches nothing. So lldb waits for a
# new wifip2pd, this script restarts the daemon to produce one, and the
# breakpoints are armed while it is still stopped at exec.
#
# WHAT IT PRINTS: every Apple80211* entry point the framework exports, with its
# first four argument registers and the status it returns. The call we are after
# is the one returning -3900.
#
# THE RISK: lldb stops wifip2pd, and this script kills it to force a relaunch.
# It is a launchd daemon, so launchd brings it straight back; the cost is that
# AirDrop discovery restarts. Nothing is evaluated or called in the target, and
# a watchdog detaches if lldb outlives the timeout (the kernel resumes a task
# whose debugger dies).
#
#   sudo tools/trace_wifip2pd.sh [seconds]
set -u

[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo tools/trace_wifip2pd.sh" >&2; exit 1; }

timeout="${1:-60}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/build/log/wifip2pd-trace.txt"
mkdir -p "$(dirname "$out")"

case "$(csrutil status)" in
*"Debugging Restrictions: enabled"*)
    echo "SIP still forbids attaching: csr-active-config needs CSR_ALLOW_TASK_FOR_PID." >&2
    echo "In RembrandtGPU: sudo tools/efi.sh csr add task_for_pid dtrace, then reboot." >&2
    exit 1 ;;
esac

cmds="$(mktemp)"
trap 'rm -f "$cmds"' EXIT

# The breakpoint is created before IO80211 is in the process, which is the
# point: lldb resolves it when the framework loads, so the very first
# Apple80211 call of the interface setup is caught too.
cat > "$cmds" <<LLDB
settings set target.process.stop-on-sharedlibrary-events false
settings set auto-confirm true
command script import $root/tools/trace_wifip2pd.py
process attach -w -n wifip2pd
rtw89_arm_awdl_trace
continue
LLDB

echo "waiting for a new wifip2pd; output -> ${out#$root/}"

( sleep "$timeout"
  pkill -INT lldb 2>/dev/null
  sleep 3
  pkill -TERM lldb 2>/dev/null
  sleep 3
  pkill -9 lldb 2>/dev/null ) &
watchdog=$!

lldb --batch -s "$cmds" > "$out" 2>&1 &
lldbpid=$!

# Give lldb time to reach `process attach -w` before there is anything to
# attach to, then make launchd produce the new wifip2pd.
sleep 4
old="$(pgrep -x wifip2pd || true)"
echo "restarting wifip2pd${old:+ (was pid $old)}"
pkill -x wifip2pd 2>/dev/null || true

wait "$lldbpid" 2>/dev/null || true
kill "$watchdog" 2>/dev/null || true

chown "${SUDO_USER:-root}" "$out" 2>/dev/null || true
echo
echo "--- calls that returned -3900 ---"
grep -n 'INVALID PARAMETERS' "$out" || echo "(none; see the trace for what ran)"
echo
echo "--- every negative return ---"
grep -n '<<<' "$out" | head -20
echo
echo "full trace: $out"
