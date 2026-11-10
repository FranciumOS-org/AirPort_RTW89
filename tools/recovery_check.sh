#!/bin/bash
# recovery_check.sh - what the Wi-Fi stack looks like from macOS Recovery.
# Run it in Recovery's Terminal (Utilities > Terminal), with the data volume
# mounted (Disk Utility mounts it); the report is written next to this script's
# repository, as recovery-report.txt.
#
#   bash "/Volumes/MACOS - Data/Users/<you>/Developer/AirPort_RTW89/tools/recovery_check.sh"
here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/recovery-report.txt"
{
    echo "== $(date) $(sw_vers 2>/dev/null | tr '\n' ' ')"
    echo "kernel: $(uname -v)"
    echo "boot-args: $(nvram boot-args 2>/dev/null | cut -f2)"
    echo "csr-active-config: $(nvram csr-active-config 2>/dev/null | cut -f2)"
    echo "== loaded kexts"
    (kmutil showloaded 2>/dev/null || kextstat 2>/dev/null) |
        grep -iE 'rtw89|IO80211|Skywalk|AMFIPass|Lilu|corecapture|CoreAnalytics' || echo "none of them"
    echo "== the card"
    ioreg -l -w0 2>/dev/null | grep -iE 'b852|8852|8922|8851|AirPort_RTW89|AirPortRTW89|IO80211|IOSkywalk' | head -60
    echo "== interfaces"
    ifconfig -a 2>/dev/null | grep -E '^[a-z0-9]+:|ether|status'
    networksetup -listallhardwareports 2>&1 | head -30
    echo "== Wi-Fi processes"
    ps ax 2>/dev/null | grep -iE 'airportd|wifi|configd' | grep -v grep
    ls -la /usr/libexec/airportd /System/Library/CoreServices/WiFiAgent.app 2>&1 | head -5
    echo "== driver and family log"
    log show --last boot --style compact --predicate \
        'sender CONTAINS "RTW89" OR sender CONTAINS "IO80211" OR sender CONTAINS "Skywalk" OR sender == "AMFIPass" OR sender == "Lilu" OR process == "airportd"' \
        2>&1 | tail -n 600
    echo "== kernel lines naming them"
    (dmesg 2>/dev/null; log show --last boot --style compact --predicate 'process == "kernel"' 2>/dev/null) |
        grep -iE 'rtw89|80211|skywalk|amfipass|lilu|can.t load|kext.*(fail|reject|denied)' | tail -n 300
} > "$out" 2>&1
echo "saved $out ($(wc -l < "$out" | tr -d ' ') lines)"
