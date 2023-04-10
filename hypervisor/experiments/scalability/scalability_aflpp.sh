# this needs to be run in aflpp folder, which is next to kvm-fuzz folder
set -e

bin="/tmp/empty"

echo "int main(){}" > /tmp/empty.c
./afl-clang-fast /tmp/empty.c -o $bin


launch() {
	./afl-fuzz -i in -o out -V 10 $1 -- $bin > /dev/null &
}

for cores in `seq 1 8`; do
	rm -rf out/
	launch "-M cpu1"
	for i in `seq 2 $cores`; do
		launch "-S cpu$i"
	done
	sleep 12
	fcps=`./afl-whatsup -d out/ |& grep "Cumulative speed" | awk '{ print $4 }'`
	scalability=`echo "scale=5; $fcps / $cores" | bc`
	echo $cores $fcps $scalability
done
