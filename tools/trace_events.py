# SPDX-License-Identifier: MIT
# Loaded by trace_events.sh. Counts the events IO80211 takes from the ring in
# wifip2pd, shows what the action frames carry, and whether wifip2pd's parser
# accepts them. The parser's addresses are for macOS 26.7.2's wifip2pd.
import time

import lldb

RUN_SECONDS = 45
CALLBACK = 0x100041fe0
PARSE_ENTRY = 0x1000cf680
PARSE_RETURN = 0x1000cf8b3
AF_HDR_LEN = 0x48
AF_FIXED_LEN = 16

counts = {}
sizes = {}
shapes = {}
parsed = {"entered": 0, "ok": 0, "threw": 0}
callback_codes = {}
closures = set()
handles = set()
slide = 0
deadline = 0


def setup(debugger):
    global slide, deadline
    deadline = time.monotonic() + RUN_SECONDS
    target = debugger.GetSelectedTarget()
    module = target.FindModule(lldb.SBFileSpec("wifip2pd"))
    slide = module.GetObjectFileHeaderAddress().GetLoadAddress(target) - 0x100000000
    print("wifip2pd slide 0x%x" % slide)
    for addr, name in ((CALLBACK, "on_callback"), (PARSE_ENTRY, "on_parse_entry"),
                       (PARSE_RETURN, "on_parse_return")):
        bp = target.BreakpointCreateByAddress(addr + slide)
        bp.SetScriptCallbackFunction("trace_events." + name)


def tlv_types(body):
    types = []
    at = AF_FIXED_LEN
    while at + 3 <= len(body):
        size = body[at + 1] | (body[at + 2] << 8)
        if at + 3 + size > len(body):
            types.append("%d!" % body[at])
            break
        types.append(str(body[at]))
        at += 3 + size
    return ",".join(types)


def on_event(frame, bp_loc, extra, internal_dict):
    process = frame.GetThread().GetProcess()
    err = lldb.SBError()
    meta = frame.FindRegister("rsi").GetValueAsUnsigned()
    data = frame.FindRegister("rdx").GetValueAsUnsigned()
    size = frame.FindRegister("rcx").GetValueAsUnsigned()
    wrapped = frame.FindRegister("r8").GetValueAsUnsigned()
    wrapped_size = frame.FindRegister("r9").GetValueAsUnsigned()
    code = process.ReadUnsignedFromMemory(meta + 0x1c, 4, err)
    handle = frame.FindRegister("rdi").GetValueAsUnsigned()
    if handle not in handles:
        handles.add(handle)
        state = process.ReadMemory(handle + 0x14, 0x21, err) or bytes(0x21)
        print("handle bound to %r, event names %r" %
              (process.ReadMemory(handle + 4, 16, err), process.ReadMemory(meta + 0x20, 16, err)))
        # Raw P2P monitoring sets +0x33 and +0x34 and takes every event; otherwise
        # the mask at +0x14 decides, bit (code - 1). Event 48 is bit 7 of byte 5.
        print("handle 0x%x: raw %d, all events %d, event 48 in mask %d, mask %s" %
              (handle, state[0x1f], state[0x20], (state[5] >> 7) & 1, state[:0x1f].hex()))
    counts[code] = counts.get(code, 0) + 1
    if not wrapped:
        wrapped_size = 0
    raw = process.ReadMemory(data, min(size, 4096), err) or b""
    if wrapped_size:
        raw += process.ReadMemory(wrapped, min(wrapped_size, 4096), err) or b""
    if code == 48 and len(raw) > AF_HDR_LEN + AF_FIXED_LEN:
        body = raw[AF_HDR_LEN:]
        sizes[len(raw)] = sizes.get(len(raw), 0) + 1
        shape = (raw[:6].hex(":"), body[6], tlv_types(body))
        if shape not in shapes:
            shapes[shape] = 0
            if len(shapes) <= 24:
                print("event 48 from %s, subtype %d, %d bytes (%d + %d), TLVs %s" %
                      (shape[0], shape[1], len(raw), size, wrapped_size, shape[2]))
        shapes[shape] += 1
    elif counts[code] <= 3:
        print("event %d, %d + %d bytes: %s" % (code, size, wrapped_size, raw[:96].hex(" ")))
    if sum(counts.values()) % 25 == 0:
        print("counts:", dict(sorted(counts.items())), "sizes:", dict(sorted(sizes.items())),
              "callback:", dict(sorted(callback_codes.items())), "parser:", parsed)
    # A breakpoint ends the run. A signal would not do: wifip2pd shuts down on
    # SIGINT even when the debugger keeps it from being delivered.
    return time.monotonic() >= deadline


def on_callback(frame, bp_loc, extra, internal_dict):
    code = frame.FindRegister("rdi").GetValueAsUnsigned() & 0xffffffff
    callback_codes[code] = callback_codes.get(code, 0) + 1
    closure = frame.FindRegister("rcx").GetValueAsUnsigned()
    if closure not in closures:
        closures.add(closure)
        print("callback for code %d, closure 0x%x, from: %s" % (code, closure - slide, " ".join(
            "0x%x" % (f.GetPC() - slide) for f in frame.GetThread().frames[:8])))
    return False


def on_parse_entry(frame, bp_loc, extra, internal_dict):
    parsed["entered"] += 1
    if parsed["entered"] <= 2:
        print("parser called from:", " ".join(
            "0x%x" % (f.GetPC() - slide) for f in frame.GetThread().frames[:12]))
    return False


def on_parse_return(frame, bp_loc, extra, internal_dict):
    parsed["threw" if frame.FindRegister("r12").GetValueAsUnsigned() else "ok"] += 1
    return False
