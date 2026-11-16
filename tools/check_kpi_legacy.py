#!/usr/bin/env python3
"""Check every import against declared KPIs and the exact injected Legacy.

The host kmutil catalogue describes the on-disk Wi-Fi family. Supplement it
with real exported symbol names from the pinned injected image. A build may
use the exact on-disk image when Legacy is absent, with an explicit option.
A different loaded image is always rejected. This does not authorize loading.
"""
from pathlib import Path
import argparse
import hashlib
import json
import plistlib
import re
import struct
import subprocess
import sys

LEGACY_ID = 'com.apple.iokit.IO80211FamilyLegacy'
LEGACY_UUID = '4C07538B-62EB-3D6D-AEF9-93BCDCF45FAB'
LEGACY_IMAGE_SHA256 = 'ac2dc15b77f8eaf97b71b34c5d0e1b59f862bfeac618396449306e1837e73894'
CATALOG_SHA256 = '483456e16a0df39e99c10079cb2208a1ea1bdda4b135f106be31253d3170c50c'

def verify_legacy_image(path):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != LEGACY_IMAGE_SHA256:
        raise ValueError('On-disk Legacy image SHA256 differs')
    if len(data) < 32 or struct.unpack_from('<II', data) != (0xfeedfacf, 0x1000007):
        raise ValueError('On-disk Legacy is not an x86_64 Mach-O image')
    at, uuids = 32, []
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        if at + 8 > len(data):
            raise ValueError('Truncated Legacy load command')
        cmd, size = struct.unpack_from('<II', data, at)
        if size < 8 or at + size > len(data):
            raise ValueError('Invalid Legacy load command')
        if cmd == 27:
            if size != 24:
                raise ValueError('Invalid Legacy UUID command')
            import uuid
            uuids.append(str(uuid.UUID(bytes=data[at + 8:at + 24])).upper())
        at += size
    if uuids != [LEGACY_UUID]:
        raise ValueError('On-disk Legacy image UUID differs')
    return {'path': str(Path(path).resolve()), 'uuid': LEGACY_UUID,
            'sha256': LEGACY_IMAGE_SHA256}

def load_legacy_catalog(path, loaded, legacy_image=None, allow_unloaded=False):
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != CATALOG_SHA256:
        raise ValueError('Legacy export catalogue bytes differ')
    catalog = json.loads(data)
    if (catalog.get('schema') != 1 or catalog.get('bundle_identifier') != LEGACY_ID or
            catalog.get('uuid') != LEGACY_UUID or catalog.get('binary_sha256') != LEGACY_IMAGE_SHA256):
        raise ValueError('Legacy export catalogue identity differs')
    exports = catalog.get('exports', [])
    if len(exports) != 3508 or exports != sorted(set(exports)):
        raise ValueError('Legacy export catalogue symbol set differs')
    rows = [l for l in loaded.splitlines() if re.search(r'(?:^|\s)' + re.escape(LEGACY_ID) + r'\s+\(', l)]
    if rows and (len(rows) != 1 or LEGACY_UUID not in rows[0].upper()):
        raise ValueError('Loaded Legacy UUID differs; disk image cannot override it')
    if legacy_image is not None:
        verify_legacy_image(legacy_image)
    if not rows and not (allow_unloaded and legacy_image is not None):
        raise ValueError('Pinned Legacy is absent; build-only checking requires the exact on-disk image')
    return catalog

def parse_providers(text):
    found = {}
    for match in re.finditer(r'^\s+(\S+) in \S+: (\S+) \(', text, re.M):
        found.setdefault(match[1], set()).add(match[2])
    return found

def validate_imports(wanted, declared, host_providers, legacy):
    wanted, declared = set(wanted), set(declared)
    if LEGACY_ID not in declared:
        raise ValueError('Bundle does not declare IO80211FamilyLegacy')
    found = {s: set(p) for s, p in host_providers.items()}
    supplemented = wanted & set(legacy['exports'])
    for symbol in supplemented:
        found.setdefault(symbol, set()).add(LEGACY_ID)
    pads = (wanted - set(found)) & set(legacy['permitted_vtable_pad_imports'])
    missing = sorted(wanted - set(found) - pads)
    undeclared = sorted(s for s in wanted & set(found) if not found[s] & declared)
    used = sorted({p for s in wanted & set(found) for p in found[s] & declared})
    return {'missing': missing, 'undeclared': undeclared, 'used_libraries': used,
            'pad_symbols': sorted(pads), 'pinned_legacy_symbols': sorted(supplemented)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--legacy-catalog', type=Path, required=True)
    parser.add_argument('--legacy-image', type=Path, help='Actual pinned Legacy executable on disk')
    parser.add_argument('--allow-unloaded-legacy', action='store_true',
                        help='Build-only: require the exact image when Legacy is absent')
    args = parser.parse_args()
    info = plistlib.loads((args.bundle / 'Contents/Info.plist').read_bytes())
    binary = args.bundle / 'Contents/MacOS' / info['CFBundleExecutable']
    declared = set(info.get('OSBundleLibraries', {}))
    nm = subprocess.run(['nm', '-u', '-j', str(binary)], capture_output=True, text=True)
    if nm.returncode:
        raise ValueError('nm could not read the native binary')
    wanted = {s.strip() for s in nm.stdout.splitlines() if s.strip()}
    if not wanted:
        raise ValueError('Native import list is unexpectedly empty')
    loaded = subprocess.run(['kmutil', 'showloaded'], capture_output=True, text=True)
    if loaded.returncode:
        raise ValueError('Cannot verify loaded Legacy UUID')
    legacy = load_legacy_catalog(args.legacy_catalog, loaded.stdout,
                                 args.legacy_image, args.allow_unloaded_legacy)
    km = subprocess.run(['kmutil', 'libraries', '-p', str(args.bundle)], capture_output=True, text=True)
    host = parse_providers(km.stdout + km.stderr)
    result = validate_imports(wanted, declared, host, legacy)
    print('  KPI %d imports; libraries used: %s' % (len(wanted), ', '.join(result['used_libraries'])))
    print('    kmutil catalogue exit: %d; every import requires a verified declared provider' % km.returncode)
    print('    pinned Legacy %s: %d imported symbols placed by exact export catalogue' %
          (LEGACY_UUID, len(result['pinned_legacy_symbols'])))
    if args.legacy_image is not None:
        print('    exact on-disk Legacy SHA256+UUID verified: ' + str(args.legacy_image))
    if not any(re.search(r'(?:^|\s)' + re.escape(LEGACY_ID) + r'\s+\(', row)
               for row in loaded.stdout.splitlines()):
        print('    Legacy absent: static build check only; runtime loader/Bridge checks still required')
    if result['pad_symbols']:
        print('    %d reviewed vtable pad slots require the kernel linker' % len(result['pad_symbols']))
    for symbol in result['missing']:
        print('    no verified provider exports ' + symbol)
    for symbol in result['undeclared']:
        print('    provider is not declared for ' + symbol)
    return int(bool(result['missing'] or result['undeclared']))

if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError) as error:
        print('KPI_CHECK_FAILED: ' + str(error), file=sys.stderr)
        sys.exit(1)
