"""Hermetic Git fixtures for dependency fetching, pinning and cache validation."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import ensure_sdk as sdk


class SDKBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.origin = self.root / "origin"
        self.origin.mkdir()
        sdk.run_git(self.origin, "init", "-q")
        files = {}
        for name in sdk.REQUIRED:
            p = self.origin / name
            p.parent.mkdir(parents=True, exist_ok=True)
            b = (name + " fixture\n").encode()
            p.write_bytes(b)
            files[name] = {"sha": hashlib.sha1(b"blob " + str(len(b)).encode() + b"\0" + b).hexdigest(),
                           "mode": "100644", "size": len(b)}
        sdk.run_git(self.origin, "add", ".")
        sdk.run_git(self.origin, "-c", "user.name=Owly test", "-c", "user.email=test@example.invalid",
                    "-c", "commit.gpgsign=false", "commit", "-qm", "SDK fixture")
        self.lock = {"repository": str(self.origin), "commit": sdk.run_git(self.origin, "rev-parse", "HEAD"),
                     "tree": sdk.run_git(self.origin, "rev-parse", "HEAD^{tree}"), "files": files}

    def test_official_layout_does_not_require_libcc_kext(self):
        self.assertTrue(sdk.valid_sdk(self.origin))
        self.assertFalse((self.origin / "Library/x86_64/libcc_kext.a").exists())
        self.assertEqual(sdk.verify_sdk(self.origin, self.lock), len(sdk.REQUIRED))

    def test_fetch_exact_commit_and_reuse_without_fetch(self):
        target = sdk.ensure_sdk(self.root / "cache", self.lock, self.root / "report")
        self.assertEqual(sdk.run_git(target, "rev-parse", "HEAD"), self.lock["commit"])
        self.assertTrue(json.loads((self.root / "report/sdk_verification.json").read_text())["downloaded_this_run"])
        real = sdk.run_git
        def no_fetch(path, *args):
            self.assertNotIn("fetch", args)
            return real(path, *args)
        with patch.object(sdk, "run_git", side_effect=no_fetch):
            self.assertEqual(sdk.ensure_sdk(self.root / "cache", self.lock, self.root / "report"), target)
        self.assertFalse(json.loads((self.root / "report/sdk_verification.json").read_text())["downloaded_this_run"])

    def test_wrong_commit_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "commit mismatch"):
            sdk.verify_sdk(self.origin, dict(self.lock, commit="0" * 40))

    def test_wrong_tree_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "tree mismatch"):
            sdk.verify_sdk(self.origin, dict(self.lock, tree="0" * 40))

    def test_modified_header_rejected(self):
        (self.origin / sdk.REQUIRED[0]).write_text("modified")
        with self.assertRaisesRegex(RuntimeError, "content mismatch"):
            sdk.verify_sdk(self.origin, self.lock)

    def test_unexpected_file_rejected(self):
        (self.origin / "unexpected.h").write_text("extra")
        with self.assertRaisesRegex(RuntimeError, "unexpected files"):
            sdk.verify_sdk(self.origin, self.lock)

    def test_failed_fetch_does_not_publish_cache(self):
        lock = dict(self.lock, repository=str(self.root / "absent"))
        with self.assertRaisesRegex(RuntimeError, "git step failed"):
            sdk.ensure_sdk(self.root / "cache", lock, self.root / "report")
        self.assertFalse((self.root / "cache" / ("MacKernelSDK-" + lock["commit"])).exists())
        self.assertEqual(list((self.root / "cache").iterdir()), [])

    def test_cached_edit_rejected_without_replacing_it(self):
        target = sdk.ensure_sdk(self.root / "cache", self.lock, self.root / "report")
        changed = target / sdk.REQUIRED[0]
        changed.write_text("changed cache")
        with self.assertRaisesRegex(RuntimeError, "content mismatch"):
            sdk.ensure_sdk(self.root / "cache", self.lock, self.root / "report")
        self.assertEqual(changed.read_text(), "changed cache")


if __name__ == "__main__":
    unittest.main(verbosity=2)
