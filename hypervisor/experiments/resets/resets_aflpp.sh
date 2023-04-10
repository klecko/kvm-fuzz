# this needs to be run in aflpp folder, which is next to kvm-fuzz folder
set -e

bin="../kvm-fuzz/zig-out/bin/resets_test"
entrypoint=0x`nm $bin | grep fuzz_start | cut -d ' ' -f 1`

for i in `seq 1000 100 10000`; do
	AFL_ENTRYPOINT=$entrypoint ./afl-fuzz -i in -o out/ -Q -V 10 -- $bin $i &> /dev/null
	result=`cat out/default/plot_data | tail -1 | cut -d ',' -f 12 | xargs` # total execs
	fcps=$((result / 10))
	echo $i $fcps
done
