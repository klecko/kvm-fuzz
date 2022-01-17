#!/usr/bin/env bash

function socket_test() {
	sleep 1
	echo "hello" | nc localhost 12345
	echo "hello" | nc localhost 12345
}

socket_test &

echo "hello" | ./zig-out/bin/tests
