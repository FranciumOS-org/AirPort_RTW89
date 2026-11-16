#!/bin/bash
set -u
OUT_DIR="$(mktemp -d "$HOME/Desktop/Owly_EB1_6_Runtime_$(date +%Y%m%d_%H%M%S)_XXXXXX")" || exit 1
/usr/bin/kmutil showloaded 2>&1 | /usr/bin/awk \
 '/com\.owly\.airlink\.eventbridge|as\.vit9696\.Lilu|com\.rtw89\.(front|driver)|IO80211FamilyLegacy|IOSkywalkFamily/' \
 > "$OUT_DIR/relevant-loaded-kexts.txt"
/usr/sbin/ioreg -r -c IOResources -l -w0 -d1 2>&1 | /usr/bin/awk '/"OwlyEB1/' \
 > "$OUT_DIR/persistent-bootstrap-status.txt"
/usr/sbin/ioreg -r -c OwlyAirLinkBridge -l -w0 > "$OUT_DIR/bridge-service.txt" 2>&1
/usr/sbin/ioreg -r -c IO80211AsyncEventUserClient -l -w0 > "$OUT_DIR/native-clients.txt" 2>&1
/usr/sbin/sysctl kern.boottime > "$OUT_DIR/boot-time.txt" 2>&1
/bin/ps -axo pid,lstart,comm | /usr/bin/awk '/\/usr\/libexec\/(airportd|wifip2pd)$/' > "$OUT_DIR/daemon-identity.txt"
/usr/sbin/ioreg -r -c OwlyAirLinkUserClient -l -w0 > "$OUT_DIR/clients.txt" 2>&1
/usr/sbin/ioreg -r -c AirPortRTW89Front -l -w0 2>&1 | /usr/bin/awk \
 '/Owly|OWLY|IOInterfaceName|IO80211VirtualInterfaceRole|IOClass/' > "$OUT_DIR/owly-registry.txt"
/usr/sbin/sysctl -n kern.bootargs 2>/dev/null | /usr/bin/awk \
 '{for(i=1;i<=NF;i++)if($i=="-owlyeb1"||$i=="-owlyeb1off"||$i~/^owlyebstage=/)print $i}' > "$OUT_DIR/activation.txt"
/sbin/ifconfig awdl0 > "$OUT_DIR/awdl0.txt" 2>&1
echo "Trang thai khoi tao da doc tu IORegistry. Sudo chi de lay them log kernel."
if sudo -v; then
    sudo /usr/bin/log show --last 10m --style compact --info --debug \
      --predicate '(eventMessage CONTAINS[c] "OwlyAirLinkBridge" OR eventMessage CONTAINS[c] "OwlyEB1") OR (process == "wifip2pd" AND (eventMessage CONTAINS "EventMonitoring" OR eventMessage CONTAINS "BindToInterface" OR eventMessage CONTAINS "IOUCResume" OR eventMessage CONTAINS "user client" OR eventMessage CONTAINS "AWDLInterface" OR eventMessage CONTAINS "awdl0"))' \
      > "$OUT_DIR/awdl-and-bootstrap.log" 2>&1
    LOG_STATUS=$?
    sudo /sbin/dmesg 2>&1 | /usr/bin/awk '/OwlyAirLinkBridge|OwlyEB1/' > "$OUT_DIR/bootstrap-dmesg.txt"
    DMESG_STATUS=${PIPESTATUS[0]}
    printf 'log_show_exit=%s\ndmesg_exit=%s\n' "$LOG_STATUS" "$DMESG_STATUS" > "$OUT_DIR/capture-status.txt"
else
    echo "Registry captured; privileged logs unavailable" > "$OUT_DIR/capture-status.txt"
fi
/usr/bin/ditto -c -k --keepParent "$OUT_DIR" "$OUT_DIR.zip" || exit 1
echo "GUI FILE NAY: $OUT_DIR.zip"
