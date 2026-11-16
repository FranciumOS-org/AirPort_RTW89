#!/bin/bash
# Modified 2026-11-15: RTLAirLink build-only host gate; runtime guards unchanged.
# Source build only; no installation.
set -euo pipefail
KIT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
    echo "Native kernel build requires macOS. Host core checks: make hosttest-sanitize"
    exit 2
fi
OUT_DIR="${OWLY_BRIDGE_BUILD_OUTPUT:?Run the parent software AWDL build_macos.sh}"
mkdir -p "$OUT_DIR/report" "$OUT_DIR/objects" "$OUT_DIR/UNQUALIFIED_DO_NOT_INSTALL"

build_main() (
    set -euo pipefail
    cd "$KIT_DIR"
    PYTHON="$(command -v python3)"
    RELEASE_VERSION="$("$PYTHON" -c 'import plistlib; print(plistlib.load(open("Info.plist", "rb"))["CFBundleVersion"])')"
    "$PYTHON" tools/verify_source.py
    "$PYTHON" tools/audit_lifecycle.py
    "$PYTHON" tools/check_build_host.py --report-dir "$OUT_DIR/report" "$@"
    MKSDK="$(cat "$OUT_DIR/report/sdk_path.txt")"
    MACOS_SDK="$(xcrun --sdk macosx --show-sdk-path)"
    CLANG="$(xcrun --sdk macosx --find clang)"
    CLANGXX="$(xcrun --sdk macosx --find clang++)"
    printf '%s\n' "$MACOS_SDK" > "$OUT_DIR/report/macos-sdk-path.txt"
    if [[ ! -r "$MACOS_SDK/usr/include/assert.h" ]]; then
        echo "MACOS_SDK_HEADERS_MISSING: $MACOS_SDK/usr/include/assert.h"
        exit 1
    fi
    RESOURCE_DIR="$("$CLANG" -print-resource-dir)"
    "$CLANG" --version > "$OUT_DIR/report/compiler.txt"
    xcodebuild -version > "$OUT_DIR/report/xcode.txt" 2>&1 || true

    # Exercise the exact C core on the target compiler before building the kext.
    "$CLANG" -arch x86_64 -isysroot "$MACOS_SDK" \
        -std=c11 -O1 -g -Wall -Wextra -Werror -pthread \
        -fsanitize=address,undefined -fno-omit-frame-pointer -Isrc \
        src/owly_event_core.c tests/test_event_core.c -o "$OUT_DIR/objects/core-check"
    "$OUT_DIR/objects/core-check" > "$OUT_DIR/report/host-core-check.txt" 2>&1
    cat "$OUT_DIR/report/host-core-check.txt"

    # Real lifecycle sources with mocked kernel APIs; no native kernel proof.
    "$CLANGXX" -arch x86_64 -isysroot "$MACOS_SDK" \
        -std=c++17 -O1 -g -Wall -Wextra -Werror -pthread \
        -fsanitize=address,undefined -fno-omit-frame-pointer \
        -Itests/bootstrap_stubs -Isrc src/Bootstrap.cpp src/Status.cpp \
        tests/test_bootstrap.cpp -o "$OUT_DIR/objects/lifecycle-check"
    "$OUT_DIR/objects/lifecycle-check" > "$OUT_DIR/report/lifecycle-model-check.txt" 2>&1
    cat "$OUT_DIR/report/lifecycle-model-check.txt"

    "$CLANGXX" -arch x86_64 -isysroot "$MACOS_SDK" \
        -std=c++17 -O1 -g -Wall -Wextra -Werror \
        -fsanitize=address,undefined -fno-omit-frame-pointer \
        -Itests/target_stubs -Isrc tests/test_lilu_targets.cpp -o "$OUT_DIR/objects/target-check"
    "$OUT_DIR/objects/target-check" > "$OUT_DIR/report/target-descriptor-check.txt" 2>&1
    cat "$OUT_DIR/report/target-descriptor-check.txt"

    # The production entitlement header, with controlled public-API responses.
    "$CLANGXX" -arch x86_64 -isysroot "$MACOS_SDK" \
        -std=c++17 -O1 -g -Wall -Wextra -Werror \
        -fsanitize=address,undefined -fno-omit-frame-pointer \
        -Itests/entitlement_stubs -Isrc tests/test_entitlement.cpp -o "$OUT_DIR/objects/entitlement-check"
    "$OUT_DIR/objects/entitlement-check" > "$OUT_DIR/report/entitlement-lookup-check.txt" 2>&1
    cat "$OUT_DIR/report/entitlement-lookup-check.txt"

    # Native class adapter transaction, retained-session races and slot guard.
    "$CLANGXX" -arch x86_64 -isysroot "$MACOS_SDK" \
        -std=c++17 -O1 -g -Wall -Wextra -Werror -pthread \
        -fsanitize=address,undefined -fno-omit-frame-pointer \
        -Isrc tests/test_native_adapter.cpp -o "$OUT_DIR/objects/native-adapter-check"
    "$OUT_DIR/objects/native-adapter-check" > "$OUT_DIR/report/native-adapter-check.txt" 2>&1
    cat "$OUT_DIR/report/native-adapter-check.txt"

    COMMON=(-arch x86_64 -mmacosx-version-min=13.0 -isysroot "$MACOS_SDK"
        -nostdinc -isystem "$RESOURCE_DIR/include" -I "$MKSDK/Headers"
        -I "$KIT_DIR/vendor/Lilu" -I "$KIT_DIR/src"
        -O2 -fno-strict-aliasing -fwrapv -mkernel -fno-exceptions
        -fno-builtin -fno-common -fno-stack-protector -fno-omit-frame-pointer
        -DKERNEL -DKERNEL_PRIVATE -DDRIVER_PRIVATE -DAPPLE -DNeXT -D__PRIVATE_SPI__
        -DPRODUCT_NAME=OwlyAirLinkBridge -DMODULE_VERSION="$RELEASE_VERSION" -DLILU_CUSTOM_KMOD_INIT=1 -DLILU_CUSTOM_IOKIT_INIT=1
        -Wall -Wextra -Wframe-larger-than=1024)
    CXX=(-std=gnu++17 -fapple-kext -fno-rtti)
    OBJS="$OUT_DIR/objects"
    echo "BUILDING: owly_event_core.c"
    "$CLANG" "${COMMON[@]}" -std=gnu11 -c src/owly_event_core.c -o "$OBJS/core.o"
    echo "BUILDING: Plugin.cpp"
    "$CLANGXX" "${COMMON[@]}" "${CXX[@]}" -c src/Plugin.cpp -o "$OBJS/plugin.o"
    echo "BUILDING: persistent Bootstrap.cpp"
    "$CLANGXX" "${COMMON[@]}" "${CXX[@]}" -c src/Bootstrap.cpp -o "$OBJS/bootstrap.o"
    echo "BUILDING: deferred Service.cpp"
    "$CLANGXX" "${COMMON[@]}" "${CXX[@]}" -c src/Service.cpp -o "$OBJS/service.o"
    echo "BUILDING: bounded Status.cpp"
    "$CLANGXX" "${COMMON[@]}" "${CXX[@]}" -c src/Status.cpp -o "$OBJS/status.o"
    echo "BUILDING: Lilu plugin_start.cpp (public SDK snapshot)"
    "$CLANGXX" "${COMMON[@]}" "${CXX[@]}" \
        -c vendor/Lilu/Library/plugin_start.cpp -o "$OBJS/start.o"
    echo "BUILDING: kmod_info.c"
    "$CLANG" "${COMMON[@]}" -std=gnu11 -c src/kmod_info.c -o "$OBJS/kmod.o"

    BUNDLE="$OUT_DIR/UNQUALIFIED_DO_NOT_INSTALL/OwlyAirLinkBridge.kext"
    mkdir -p "$BUNDLE/Contents/MacOS"
    cp Info.plist "$BUNDLE/Contents/Info.plist"
    cp LICENSE "$OUT_DIR/UNQUALIFIED_DO_NOT_INSTALL/LICENSE-Owly-GPL2.txt"
    cp vendor/Lilu/LICENSE.txt "$OUT_DIR/UNQUALIFIED_DO_NOT_INSTALL/LICENSE-Lilu.txt"
    cp vendor/Lilu/HDE_LICENSE.TXT "$OUT_DIR/UNQUALIFIED_DO_NOT_INSTALL/LICENSE-HDE.txt"
    if [[ -f "$MKSDK/LICENSE.txt" ]]; then
        cp "$MKSDK/LICENSE.txt" "$OUT_DIR/UNQUALIFIED_DO_NOT_INSTALL/LICENSE-MacKernelSDK.txt"
    fi
    "$CLANGXX" -arch x86_64 -mmacosx-version-min=13.0 -isysroot "$MACOS_SDK" \
        -nostdlib -Xlinker -kext -L "$MKSDK/Library/x86_64" \
        "$OBJS/core.o" "$OBJS/plugin.o" "$OBJS/bootstrap.o" "$OBJS/service.o" "$OBJS/status.o" "$OBJS/start.o" "$OBJS/kmod.o" \
        -lkmod -o "$BUNDLE/Contents/MacOS/OwlyAirLinkBridge"
    /usr/bin/plutil -lint "$BUNDLE/Contents/Info.plist"
    /usr/bin/codesign --force --sign - --timestamp=none "$BUNDLE"
    /usr/bin/codesign --verify --deep --strict --verbose=2 "$BUNDLE"
    xcrun dwarfdump --uuid "$BUNDLE/Contents/MacOS/OwlyAirLinkBridge" \
        > "$OUT_DIR/report/candidate-uuid.txt"
    xcrun nm -u "$BUNDLE/Contents/MacOS/OwlyAirLinkBridge" \
        > "$OUT_DIR/report/undefined-symbols.txt"
    xcrun nm -g "$BUNDLE/Contents/MacOS/OwlyAirLinkBridge" \
        > "$OUT_DIR/report/exported-symbols.txt"
    /usr/bin/shasum -a 256 "$BUNDLE/Contents/MacOS/OwlyAirLinkBridge" \
        > "$OUT_DIR/report/candidate-sha256.txt"
    cp SOURCE_SHA256.json VENDOR_PROVENANCE.json SDK_LOCK.json "$OUT_DIR/report/"
    cp collect_runtime.sh "$OUT_DIR/collect_runtime.sh"
    echo "NATIVE_COMPILE_PASSED; binary review and USB boot qualification pending."
)

set +e
build_main "$@" 2>&1 | tee "$OUT_DIR/build.log"
BUILD_STATUS=${PIPESTATUS[0]}
set -e
if [[ "$BUILD_STATUS" == 0 ]]; then
    printf '%s\n' 'NATIVE_COMPILED_UNQUALIFIED' > "$OUT_DIR/STATUS.txt"
else
    printf '%s\n' 'BUILD_OR_PREFLIGHT_FAILED' > "$OUT_DIR/STATUS.txt"
fi
printf '%s\n' \
    'Review this newly compiled bridge before a boot test.' \
    'No kext was loaded. Runtime interoperability and AirDrop are NOT proven.' \
    > "$OUT_DIR/READ_ME_FIRST.txt"
# Object files and the host executable are intermediate, not useful for review.
rm -rf "$OUT_DIR/objects"
ZIP_PATH="$OUT_DIR.zip"
/usr/bin/ditto -c -k --keepParent "$OUT_DIR" "$ZIP_PATH"
echo ""
echo "GUI FILE NAY: $ZIP_PATH"
echo "Build result: $(cat "$OUT_DIR/STATUS.txt"). Chua nap kext vao EFI."
exit "$BUILD_STATUS"
