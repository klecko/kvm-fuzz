zig build -Drelease-safe -Dcoverage=none
measure_with_cores() {
	cases=`timeout 10 ./zig-out/bin/kvm-fuzz -j $1 -- ./test_bins/readelf-static -a input | grep cases | tail -1 | cut -d ' ' -f 3 | cut -d ',' -f 1`
	fcps=$((cases / 10))
	echo $fcps
}

nproc=`nproc`
for i in `seq 1 $nproc`; do
	fcps=`measure_with_cores $i`
	scalability=`echo "scale=5; $fcps / $i" | bc`
	echo $i $fcps $scalability
done