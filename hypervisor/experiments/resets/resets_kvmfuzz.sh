# for i in `seq 1000 100 10000`; do
for i in `seq 9000 100 10000`; do
	output=`./zig-out/bin/resets_exp $i | grep '\['`
	fcps=`echo $output | awk '{print $3}' | cut -d ',' -f 1`
	echo $i $fcps
done