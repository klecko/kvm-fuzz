# this needs to be run in aflpp folder, which is next to kvm-fuzz folder
set -e

for i in `seq 1000 100 10000`; do
	gcc nyx_mode/custom_harness/example.c -DNO_PT_NYX -DNUM_DIRTY_PAGES=$i -static -I nyx_mode/packer/ -o /tmp/nyx_custom_agent/target
	./afl-fuzz -i in -o out/ -X -V 10 /tmp/nyx_custom_agent/ &> /dev/null
	result=`cat out/default/plot_data | tail -1 | cut -d ',' -f 12 | xargs` # total execs
	fcps=$((result / 10))
	echo $i $fcps
done
