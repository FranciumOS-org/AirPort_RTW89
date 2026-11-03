#!/bin/bash
# trace_wifip2pd.sh - find the Apple80211 call that makes wifip2pd's
# AWDLInterface init fail with <Apple80211Error Invalid Parameters> (-3900).
#
# WHY LLDB AND NOT DTRACE: csr-active-config is 0xA43, so
# CSR_ALLOW_UNRESTRICTED_DTRACE (0x20) is clear and the pid provider is
# unavailable. CSR_ALLOW_TASK_FOR_PID (0x4) is clear too, but
# amfi_get_out_of_my_way=0x1 is in boot-args and lldb attaches anyway -
# RembrandtGPU's tools/wsread.sh does the same to WindowServer.
#
# WHAT IT DOES: breaks on every Apple80211* entry point in the IO80211
# framework, prints the first four argument registers, steps out, prints the
# returned status, and continues. The call we are after is the one whose
# return is -3900 (0xfffff0c4).
#
# THE RISK: lldb stops wifip2pd while attached. That is a daemon launchd
# restarts, not the compositor, so the worst case is that AirDrop discovery
# stalls for the duration. The script evaluates nothing in the target, runs
# lldb in --batch with an explicit detach, and arms a watchdog that SIGKILLs
# lldb if it outlives the timeout (the kernel resumes a task whose debugger
# dies).
#
#   sudo tools/trace_wifip2pd.sh [seconds]
#
# While it runs, make something ask for AWDL so wifip2pd retries the init:
# open a Finder window and click AirDrop in the sidebar, or open the Share
# sheet. The failure appeared in the log every time sharingd connected.
set -u

[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo tools/trace_wifip2pd.sh" >&2; exit 1; }

timeout="${1:-90}"
pid="$(pgrep -x wifip2pd || true)"
[ -n "$pid" ] || { echo "wifip2pd is not running" >&2; exit 1; }

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/build/log/wifip2pd-trace.txt"
mkdir -p "$(dirname "$out")"

cmds="$(mktemp)"
trap 'rm -f "$cmds"' EXIT

cat > "$cmds" <<'LLDB'
settings set target.process.stop-on-sharedlibrary-events false
settings set auto-confirm true
# Every Apple80211 entry point the framework exports. -s keeps the regex off
# the rest of the address space, where it would match thousands of symbols.
breakpoint set -r '^Apple80211' -s IO80211
# The id, not the -N name: `breakpoint command add` takes a breakpt-id, and -N
# is not one of its options. The regex breakpoint above is the first one set,
# so it is always 1.
breakpoint command add 1
bt 1
register read rdi rsi rdx rcx
thread step-out
register read rax
continue
DONE
continue
LLDB

echo "attaching to wifip2pd (pid $pid) for ${timeout}s; output -> ${out#$root/}"
echo "now trigger it: Finder -> AirDrop in the sidebar, or a Share sheet"

# The last `continue` in the command file blocks for as long as the process
# runs, so the watchdog is what ends the session: TERM first, so lldb detaches
# cleanly and flushes the trace, then -9 as the backstop.
( sleep "$timeout"
  pkill -INT lldb 2>/dev/null
  sleep 3
  pkill -TERM lldb 2>/dev/null
  sleep 3
  pkill -9 lldb 2>/dev/null ) &
watchdog=$!

lldb -p "$pid" --batch \
     -s "$cmds" \
     -o "process detach" \
     > "$out" 2>&1 &
lldbpid=$!

wait "$lldbpid" 2>/dev/null || true
kill "$watchdog" 2>/dev/null || true

chown "${SUDO_USER:-root}" "$out" 2>/dev/null || true
echo
echo "--- calls that returned -3900 ---"
grep -B 12 'fffff0c4\|-3900' "$out" | tail -60 || echo "(none seen; nothing triggered the init?)"
echo
echo "full trace: $out"
