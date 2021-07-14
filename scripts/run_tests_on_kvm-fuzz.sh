if [ $# -lt 1 ]
then
	echo "usage: $0 kernel_path"
	exit
fi

hypervisor/kvm-fuzz -k $1 -t 0 -m 32M --single-run=../tests/input_hello_world -f ../tests/input_hello_world -- ./tests/tests
