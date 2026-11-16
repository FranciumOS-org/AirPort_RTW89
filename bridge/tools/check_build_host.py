#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Added 2026-11-15 for standalone RTLAirLink source builds.
"""Check the build platform and explicit SDK without requiring loaded Owly kexts."""
import argparse
import json
import platform
import subprocess
from pathlib import Path
from ensure_sdk import valid_sdk

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--report-dir', type=Path, required=True)
parser.add_argument('--sdk', type=Path, required=True)
args = parser.parse_args()
if platform.system() != 'Darwin' or platform.machine() != 'x86_64':
    raise SystemExit('Build requires macOS x86_64')
version = subprocess.check_output(['/usr/bin/sw_vers', '-buildVersion'], text=True).strip()
if version != '25G241':
    raise SystemExit('This experimental build is checked only against macOS 25G241')
sdk = args.sdk.expanduser().resolve()
if not valid_sdk(sdk):
    raise SystemExit('Incomplete MacKernelSDK')
args.report_dir.mkdir(parents=True, exist_ok=True)
(args.report_dir / 'sdk_path.txt').write_text(str(sdk) + '\n')
(args.report_dir / 'host_identity.json').write_text(json.dumps({
    'status': 'BUILD_HOST_CHECK_PASSED', 'macos_build': version,
    'loaded_kext_identity_checked': False, 'runtime_compatibility_proven': False,
    'note': 'Build-only gate; runtime UUID/prefix/stage guards remain in production code.'
}, indent=2) + '\n')
print('Build host/SDK ready; runtime compatibility is not established by compilation.')
