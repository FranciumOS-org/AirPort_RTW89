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

# Fields of the Apple80211 handle that rdi points at.
# Apple80211BindToInterfaceWithService copies the interface name into +4
# ("movl $0x10, %edx" over "leaq 0x4(%r14), %r13"), and keeps the user client
# connection in +0x17c: Apple80211EventMonitoringInitIOUC returns -3900 the
# moment it reads that as zero, which is the only way the AWDL init can fail
# with Invalid Parameters.
REF_NAME = 0x04
REF_IOUC = 0x17c

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


def _ref(frame):
    """The interface name and user client connection of the handle in rdi."""
    ref = _u64(frame, "rdi")
    if not ref:
        return ""
    proc = frame.GetThread().GetProcess()
    err = lldb.SBError()
    name = proc.ReadCStringFromMemory(ref + REF_NAME, 17, err)
    if err.Fail():
        return ""
    iouc = proc.ReadUnsignedFromMemory(ref + REF_IOUC, 4, lldb.SBError())
    return " [%s iouc=%#x]" % (name.strip() or "?", iouc)


def on_call(frame, bp_loc, extra, internal_dict):
    name = frame.GetFunctionName() or "?"
    print("%-50s rdi=%#x rsi=%#x rdx=%#x rcx=%#x%s"
          % (name, _u64(frame, "rdi"), _u64(frame, "rsi"),
             _u64(frame, "rdx"), _u64(frame, "rcx"), _ref(frame)))

    _arm_return(frame, name)
    return False


def _arm_return(frame, name):
    thread = frame.GetThread()
    parent = thread.GetFrameAtIndex(1)
    if not parent.IsValid():
        return
    ret = parent.GetPC()
    if ret not in _retbp:
        target = thread.GetProcess().GetTarget()
        bp = target.BreakpointCreateByAddress(ret)
        bp.SetScriptCallbackFunction("trace_wifip2pd.on_return")
        _retbp[ret] = bp.GetID()
    _names.setdefault(ret, []).append(name)


def on_service_open(frame, bp_loc, extra, internal_dict):
    """IOServiceOpen(service, owningTask, type, &connect).

    The user client the AWDL init wants is opened here, and for an AWDL virtual
    interface IO80211VirtualInterface::newUserClient accepts only type 4 (role
    6); anything else it logs as an invalid userClient type request. If this is
    never called for awdl0, nothing in userspace ever asked for the connection.
    """
    print("IOServiceOpen   service=%#x task=%#x type=%d out=%#x"
          % (_u64(frame, "rdi"), _u64(frame, "rsi"),
             _u64(frame, "rdx") & 0xffffffff, _u64(frame, "rcx")))
    _arm_return(frame, "IOServiceOpen")
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

    # IOServiceOpen is where the user client whose absence returns -3900 would
    # be created, so it is worth watching wherever in the process it is called
    # from, not only out of IO80211.
    uc = target.BreakpointCreateByName("IOServiceOpen")
    uc.SetScriptCallbackFunction("trace_wifip2pd.on_service_open")

    print("armed %d Apple80211 locations, %d on IOServiceOpen"
          % (bp.GetNumLocations(), uc.GetNumLocations()))


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        "command script add -f trace_wifip2pd.arm rtw89_arm_awdl_trace")
