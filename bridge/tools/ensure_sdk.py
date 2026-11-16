#!/usr/bin/env python3
"""Fetch the pinned public build dependency into this kit and verify every blob."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REQUIRED = (
    "Headers/IOKit/IOUserClient.h", "Headers/IOKit/IOInterruptEventSource.h",
    "Headers/mach/kmod.h", "Library/x86_64/libkmod.a",
)


def valid_sdk(path):
    return all((path / name).is_file() for name in REQUIRED)


def run_git(path, *arguments):
    env = os.environ.copy()
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
    try:
        result = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
             "-C", str(path), *arguments],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=120, check=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError("SDK git step failed: " + (error.stdout or "")[-2500:]) from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("SDK network/git step timed out; no kernel compilation was attempted") from error
    return result.stdout.strip()


def verify_sdk(path, lock):
    if path.is_symlink() or not valid_sdk(path):
        raise RuntimeError("SDK layout is incomplete (Headers and x86_64 libkmod required)")
    if run_git(path, "rev-parse", "HEAD") != lock["commit"]:
        raise RuntimeError("SDK commit mismatch")
    if run_git(path, "rev-parse", "HEAD^{tree}") != lock["tree"]:
        raise RuntimeError("SDK tree mismatch")
    total = 0
    for name, pin in lock["files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or pin["mode"] not in ("100644", "100755"):
            raise RuntimeError("Unsupported SDK manifest entry: " + name)
        item = path / relative
        if item.is_symlink() or not item.is_file() or path.resolve() not in item.resolve().parents:
            raise RuntimeError("Missing/unsafe SDK file: " + name)
        content = item.read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if blob != pin["sha"]:
            raise RuntimeError("SDK content mismatch: " + name)
        total += 1
    if run_git(path, "status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError("SDK working tree has changes or unexpected files")
    return total


def ensure_sdk(cache_parent, lock, report_dir):
    if not shutil.which("git"):
        raise RuntimeError("Xcode Command Line Tools git is required to fetch the SDK")
    cache_parent.mkdir(parents=True, exist_ok=True)
    target = cache_parent / ("MacKernelSDK-" + lock["commit"])
    downloaded = False
    if not target.exists():
        print("SDK: fetching pinned MacKernelSDK " + lock["commit"], flush=True)
        # No changes to an existing SDK, checkout or user git configuration.
        with tempfile.TemporaryDirectory(prefix="sdk-fetch-", dir=str(cache_parent)) as work:
            stage = Path(work) / "sdk"
            stage.mkdir()
            run_git(stage, "init", "-q")
            run_git(stage, "fetch", "--quiet", "--depth=1", "--no-tags",
                    "--no-recurse-submodules", lock["repository"], lock["commit"])
            run_git(stage, "checkout", "--quiet", "--detach", "FETCH_HEAD")
            verify_sdk(stage, lock)
            try:
                stage.rename(target)
                downloaded = True
            except FileExistsError:
                pass  # another concurrent build may have populated the same cache
    count = verify_sdk(target, lock)
    report = {"repository": lock["repository"], "commit": lock["commit"],
              "tree": lock["tree"], "blob_files_verified": count,
              "downloaded_this_run": downloaded, "status": "SDK_VERIFIED"}
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "sdk_verification.json").write_text(json.dumps(report, indent=2) + "\n")
    print("SDK_VERIFIED: " + str(count) + " files; commit/tree matched", flush=True)
    return target.resolve()
