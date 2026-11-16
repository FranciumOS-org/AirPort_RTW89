HOST_CC ?= cc
HOST_FLAGS := -std=c11 -O1 -g -Wall -Wextra -Werror -fno-omit-frame-pointer -pthread

.PHONY: hosttest hosttest-sanitize clean
hosttest: build/host-test
	./build/host-test

hosttest-sanitize: build/host-test-sanitize
	ASAN_OPTIONS=detect_leaks=0 ./build/host-test-sanitize

build/host-test: src/owly_event_core.c src/owly_event_core.h tests/test_event_core.c
	mkdir -p build
	$(HOST_CC) $(HOST_FLAGS) -Isrc src/owly_event_core.c tests/test_event_core.c -o $@

build/host-test-sanitize: src/owly_event_core.c src/owly_event_core.h tests/test_event_core.c
	mkdir -p build
	$(HOST_CC) $(HOST_FLAGS) -fsanitize=address,undefined -Isrc src/owly_event_core.c tests/test_event_core.c -o $@

clean:
	rm -rf build

HOST_CXX ?= c++
.PHONY: bootstrap-hosttest
bootstrap-hosttest:
	mkdir -p build
	$(HOST_CXX) -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -pthread -Itests/bootstrap_stubs -Isrc src/Bootstrap.cpp src/Status.cpp tests/test_bootstrap.cpp -o build/test-bootstrap
	ASAN_OPTIONS=detect_leaks=0 ./build/test-bootstrap

.PHONY: target-hosttest
target-hosttest:
	mkdir -p build
	$(HOST_CXX) -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Itests/target_stubs -Isrc tests/test_lilu_targets.cpp -o build/test-targets
	ASAN_OPTIONS=detect_leaks=0 ./build/test-targets

.PHONY: entitlement-hosttest
entitlement-hosttest:
	mkdir -p build
	$(HOST_CXX) -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Itests/entitlement_stubs -Isrc tests/test_entitlement.cpp -o build/test-entitlement
	ASAN_OPTIONS=detect_leaks=0 ./build/test-entitlement

.PHONY: native-adapter-hosttest
native-adapter-hosttest:
	mkdir -p build
	$(HOST_CXX) -std=c++17 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -pthread -Isrc tests/test_native_adapter.cpp -o build/test-native-adapter
	ASAN_OPTIONS=detect_leaks=0 ./build/test-native-adapter

