function socket_test() {
	sleep 1
	echo "hello" | nc localhost 12345
	echo "hello" | nc localhost 12345
}

socket_test &

echo "hello" | ./tests/tests
