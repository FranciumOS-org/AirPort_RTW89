#!/usr/bin/env python3
"""Verify the source kit and vendored SDK content; never touches host settings."""
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    entries = json.loads((root / "SOURCE_SHA256.json").read_text())
    for name, expected in entries.items():
        path = root / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise SystemExit("SOURCE_CHECK_FAILED: " + name)
    vendor = json.loads((root / "VENDOR_PROVENANCE.json").read_text())
    for entry in vendor["files"]:
        data = (root / entry["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise SystemExit("VENDOR_CHECK_FAILED: " + entry["path"])
    print("SOURCE_CHECK_PASSED files=" + str(len(entries)))


if __name__ == "__main__":
    main()
