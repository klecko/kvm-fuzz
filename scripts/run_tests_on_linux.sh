#!/usr/bin/env bash
set -e

zig build syscalls_tests

function socket_test() {
	sleep 3
	echo "hello" | nc localhost 12345
	echo "hello" | nc localhost 12345
}

socket_test &

echo "hello" | ./zig-out/bin/syscalls_tests
