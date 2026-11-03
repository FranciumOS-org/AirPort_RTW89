"""lldb breakpoint callbacks for tools/trace_wifip2pd.sh.

Logs every Apple80211* entry point wifip2pd calls, with its first four
argument registers and the status it returns. The call we are after is the one
that returns -3900, Apple80211Error.invalidParameters, which is what makes
wifip2pd's AWDLInterface init throw and the interface get torn down again.

The return value is read with a breakpoint on the caller's return address, not
with `thread step-out`: a breakpoint callback must not resume the target, and
stepping from inside one deadlocks as often as it works. One breakpoint is kept
per return address and reused - SetOneShot does not remove a breakpoint whose
callback returns False, so creating one per call left a stale breakpoint at the
address and every later return was reported once per call that had passed
through it. The breakpoint carries nothing to say which call it belongs to, so
the names ride alongside in _names, a stack per address for recursion.
"""
import lldb

INVALID_PARAMETERS = -3900   # Apple80211Error.invalidParameters

_retbp = {}    # return address -> breakpoint id
_names = {}    # return address -> stack of function names still outstanding


def _u64(frame, name):
    v = frame.FindRegister(name)
    return v.GetValueAsUnsigned() if v.IsValid() else 0


def _s32(frame, name):
    v = frame.FindRegister(name)
    if not v.IsValid():
        return 0
    n = v.GetValueAsUnsigned() & 0xffffffff
    return n - (1 << 32) if n & 0x80000000 else n


def on_call(frame, bp_loc, extra, internal_dict):
    name = frame.GetFunctionName() or "?"
    print("%-50s rdi=%#x rsi=%#x rdx=%#x rcx=%#x"
          % (name, _u64(frame, "rdi"), _u64(frame, "rsi"),
             _u64(frame, "rdx"), _u64(frame, "rcx")))

    thread = frame.GetThread()
    parent = thread.GetFrameAtIndex(1)
    if parent.IsValid():
        ret = parent.GetPC()
        if ret not in _retbp:
            target = thread.GetProcess().GetTarget()
            bp = target.BreakpointCreateByAddress(ret)
            bp.SetScriptCallbackFunction("trace_wifip2pd.on_return")
            _retbp[ret] = bp.GetID()
        _names.setdefault(ret, []).append(name)
    return False


def on_return(frame, bp_loc, extra, internal_dict):
    rax = _s32(frame, "rax")
    stack = _names.get(frame.GetPC(), [])
    name = stack.pop() if stack else "?"
    if rax == INVALID_PARAMETERS:
        flag = "   <<<<<< INVALID PARAMETERS"
    elif rax < 0:
        flag = "   <<< negative"
    else:
        flag = ""
    print("  -> %-46s returns %d (%#010x)%s" % (name, rax, rax & 0xffffffff, flag))
    return False


def arm(debugger, command, result, internal_dict):
    """`arm` as an lldb command: break on every Apple80211* entry point."""
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByRegex(r"^Apple80211", "IO80211")
    bp.SetScriptCallbackFunction("trace_wifip2pd.on_call")
    print("armed %d locations" % bp.GetNumLocations())


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        "command script add -f trace_wifip2pd.arm rtw89_arm_awdl_trace")
