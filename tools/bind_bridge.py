#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bind RTLAirLink's bridge to the front built alongside it.

    bind_bridge.py UUID SRC_Plugin.cpp OUT_Plugin.cpp   write a copy with the UUID
    bind_bridge.py --check UUID BINARY                  the UUID is in it exactly once

The bridge refuses to hook anything unless the loaded front has this UUID
(kFrontendUUID in Plugin.cpp), so it is written in at build time, as
RTLAirLink's build.py does.
"""
import re
import sys


def raw(uuid):
    b = bytes.fromhex(uuid.replace('-', ''))
    if len(b) != 16:
        sys.exit('bind_bridge: not a UUID: %r' % uuid)
    return b


if len(sys.argv) == 4 and sys.argv[1] == '--check':
    n = open(sys.argv[3], 'rb').read().count(raw(sys.argv[2]))
    if n != 1:
        sys.exit('bind_bridge: the front UUID is in the bridge %d times, not once' % n)
elif len(sys.argv) == 4:
    b = raw(sys.argv[1])
    text = open(sys.argv[2]).read()
    new = 'constexpr uint8_t kFrontendUUID[16] = {\n    ' + ','.join('0x%02x' % x for x in b) + '\n};'
    text, n = re.subn(r'constexpr uint8_t kFrontendUUID\[16\] = \{[^}]+\};', new, text)
    if n != 1:
        sys.exit('bind_bridge: kFrontendUUID found %d times in %s' % (n, sys.argv[2]))
    open(sys.argv[3], 'w').write(text)
else:
    sys.exit(__doc__)
