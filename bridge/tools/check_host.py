#!/usr/bin/env python3
"""Read-only host/SDK identity gate for EB1. Reports contain no credentials."""
import argparse
import json
import platform
import re
import subprocess
from pathlib import Path
from ensure_sdk import ensure_sdk, valid_sdk, verify_sdk

PINS = {'as.vit9696.Lilu': '38ACFA46-F60C-3795-B868-EF32F98C78ED', 'com.apple.iokit.IO80211FamilyLegacy': '4C07538B-62EB-3D6D-AEF9-93BCDCF45FAB', 'com.apple.iokit.IOSkywalkFamily': '035A9AD9-6CDE-362F-8DEC-B664BC6431EC', 'com.rtw89.driver': '5B55BA94-0573-37F0-A3B7-CA021167C0A3', 'com.rtw89.front': 'C79557B8-3F1C-3998-91BF-33B3F1F48D37', 'com.owly.airlink.eventbridge': '25DC81B8-52BC-38E8-9604-3A9190C8C1CA'}


def capture(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


def locate_sdk(explicit, report_dir):
    if explicit:
        chosen = Path(explicit).expanduser().resolve()
        if not valid_sdk(chosen):
            raise RuntimeError("--sdk must point to a complete MacKernelSDK (Headers + Library/x86_64)")
        return chosen
    kit = Path(__file__).resolve().parents[1]
    lock = json.loads((kit / "SDK_LOCK.json").read_text())
    old_cache = Path.home() / "Downloads/Owly-AirLink-EventBridge-EB1-SDKFix-2026-11-09/dependencies" / ("MacKernelSDK-" + lock["commit"])
    if old_cache.exists():
        count = verify_sdk(old_cache, lock)
        (report_dir / "sdk_verification.json").write_text(json.dumps({
            "status": "SDK_VERIFIED", "commit": lock["commit"], "tree": lock["tree"],
            "blob_files_verified": count, "reused_previous_eb1_cache": True,
            "downloaded_this_run": False}, indent=2) + "\n")
        print("SDK_VERIFIED: reusing previous EB1 cache; " + str(count) + " files")
        return old_cache
    return ensure_sdk(kit / "dependencies", lock, report_dir)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--sdk")
    args = parser.parse_args()
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    report = {"status": "PREFLIGHT_FAILED", "native_compiled": False,
              "installed": False, "airdrop_proven": False, "expected_loaded_uuids": PINS}
    try:
        if platform.system() != "Darwin" or platform.machine() != "x86_64":
            raise RuntimeError("Native build requires the x86_64 LOQ running macOS")
        report["macos_build"] = capture(["/usr/bin/sw_vers", "-buildVersion"]).strip()
        if report["macos_build"] != "25G241":
            raise RuntimeError("macOS build does not match pinned 25G241")
        loaded = capture(["/usr/bin/kmutil", "showloaded"])
        # Retain only relevant lines (no full hardware, boot args or system inventory).
        selected = []
        for bundle, uuid in PINS.items():
            matches = [line for line in loaded.splitlines()
                       if re.search(r"(?:^|\s)" + re.escape(bundle) + r"\s+\(", line)]
            if len(matches) != 1 or uuid not in matches[0].upper():
                raise RuntimeError("Loaded UUID mismatch or absent bundle: " + bundle)
            selected.append(matches[0])
        (report_dir / "loaded-pinned-kexts.txt").write_text("\n".join(selected) + "\n")
        report["host_identity_passed"] = True
        sdk = locate_sdk(args.sdk, report_dir)
        report["sdk_selection"] = "explicit_path" if args.sdk else "pinned_auto_fetch"
        report["mac_kernel_sdk"] = str(sdk)
        report["status"] = "PREFLIGHT_PASSED"
        (report_dir / "sdk_path.txt").write_text(str(sdk) + "\n")
        print("PREFLIGHT_PASSED: exact LOQ build/kext identities; SDK ready")
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        report["error"] = str(error)
        print("PREFLIGHT_FAILED: " + str(error))
        raise SystemExit(1)
    finally:
        (report_dir / "host_identity.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
