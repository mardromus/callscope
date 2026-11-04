# Convenience wrapper around CMake. Everything real lives in CMakeLists.txt.
BUILD ?= build
JOBS  ?= $(shell nproc 2>/dev/null || echo 4)

.PHONY: all build test asan demo format lint clean

all: build

build:
	cmake -S . -B $(BUILD) -DCMAKE_BUILD_TYPE=RelWithDebInfo
	cmake --build $(BUILD) -j $(JOBS)

test: build
	ctest --test-dir $(BUILD) --output-on-failure

asan:
	cmake -S . -B build-asan -DCALLSCOPE_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
	cmake --build build-asan -j $(JOBS)
	ctest --test-dir build-asan --output-on-failure

demo: build
	./scripts/demo.sh $(BUILD)

format:
	find src include tests examples -name '*.[ch]' | xargs clang-format -i

lint:
	cppcheck --enable=warning,performance,portability --inline-suppr --error-exitcode=1 \
	  -I include --suppress=missingIncludeSystem src

clean:
	rm -rf $(BUILD) build-asan
