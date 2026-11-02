#!/usr/bin/env python3
"""List the symbols a binary still needs from the kernel, and whoever else links it.

Usage: python3 tools/check_imports.py <binary> [report.md] [--also <binary>...]

Every undefined symbol must be something the running kernel has, or something
one of the --also binaries exports; anything else is a function nobody
provides, and the script fails.

For the front this is not a formality. It links against an injected
IO80211FamilyLegacy, and a symbol it needs and that family lacks is not a
build error: the kext simply does not load at boot, which here meant no Wi-Fi
at all and no panic to say why. Subclassing one of the family's classes is how
it happens -- overriding a single method puts that class's whole vtable in
ours, every slot of it a symbol that has to resolve.

The kernel's symbol table is a superset of what kexts may link against, so a
pass here does not replace `kmutil libraries` on the finished kext.
"""
import subprocess
import sys
from pathlib import Path

KERNEL = Path("/System/Library/Kernels/kernel")
# IONetworkingFamily, IOPCIFamily and the rest live only inside the boot
# collection on this macOS; they are not separate binaries to point nm at.
KEXT_COLLECTION = Path("/System/Library/KernelCollections/BootKernelExtensions.kc")
# Defined by whatever the driver objects are linked into, not by the kernel:
# the kext (src/kext/rtw89_logring.cpp) and the hosttest (host_kernel.c).
PROVIDED_ELSEWHERE = {"_rtw89_iolog"}

# IONetworkController's vtable padding. nm finds slots 8 and up in the boot
# collection and not these two, but every front this project has shipped
# carries the same two references and loads, so they resolve at load time and
# the collection's table is simply not where to look for them. Listed one by
# one rather than by prefix: a genuinely missing slot should still fail.
PAD_SLOTS = {
    "__ZN19IONetworkController29_RESERVEDIONetworkController6Ev",
    "__ZN19IONetworkController29_RESERVEDIONetworkController7Ev",
}


def symbols(path, flag):
    out = subprocess.run(["nm", flag, "-j", str(path)], capture_output=True, text=True)
    return {line.strip() for line in out.stdout.splitlines() if line.strip()}


def main():
    argv = sys.argv[1:]
    also = []
    if "--also" in argv:
        i = argv.index("--also")
        also = [Path(a) for a in argv[i + 1:]]
        argv = argv[:i]

    obj = Path(argv[0])
    undefined = sorted(symbols(obj, "-u") - PROVIDED_ELSEWHERE)
    if not KERNEL.exists():
        print(f"{len(undefined)} undefined symbols; no {KERNEL} to check them against")
        return 0
    provided = symbols(KERNEL, "-g")
    if KEXT_COLLECTION.exists():
        provided |= symbols(KEXT_COLLECTION, "-g")
    for a in also:
        if not a.exists():
            print(f"    missing: {a} is not here to check against")
            return 1
        provided |= symbols(a, "-g")
    unresolved = [s for s in undefined if s not in provided and s not in PAD_SLOTS]

    if len(argv) > 1:
        lines = ["# Kernel imports", "",
                 f"Symbols `{obj.name}` leaves for others to resolve: "
                 f"**{len(undefined)}**, unresolved: **{len(unresolved)}**.", ""]
        lines += [f"- `{s[1:]}`" + ("  **(nobody has this)**" if s in unresolved else "")
                  for s in undefined]
        Path(argv[1]).write_text("\n".join(lines) + "\n")

    print(f"  LINK {obj}: {len(undefined)} imports, {len(unresolved)} unresolved")
    for s in unresolved:
        print(f"    missing: {s[1:]}")
    return 1 if unresolved else 0


if __name__ == "__main__":
    sys.exit(main())
