#!/usr/bin/env bash
set -e

zig build -Dcoverage=none -Denable-guest-output
zig build syscalls_tests
mkdir -p in
if [ -z "$(ls -A in)" ]; then
	touch in/1
fi
zig-out/bin/kvm-fuzz -t 0 -m 512M --single-run=./tests/input_hello_world \
	-f ./tests/input_hello_world -- zig-out/bin/syscalls_tests "$@"
