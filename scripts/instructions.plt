set title "Instructions executed by 'readelf -a' in each ring"
set ylabel "Instructions"
set grid
set multiplot layout 2,2
set format y "%.0tx10^{%T}"

# set format y "%.0sx10^{%T}"

set style data histogram
set style histogram rowstacke
set style fill solid border -1
set boxwidth 0.7
set key autotitle columnhead

set title "readelf -a /bin/ls"
set ytics 2e+06
plot "./stats_instructions_readelf-a.txt" using 2:xtic(1), '' using 3

set title "readelf -l /bin/ls"
set ytics 2e+05
plot "./stats_instructions_readelf-l.txt" using 2:xtic(1), '' using 3

set title "tiff2rgba big\\_file"
set yrange [ 0 : 5.2e+07 ]
set ytics 1e+07
plot "./stats_instructions_libtiff1MB.txt" using 2:xtic(1), '' using 3

set title "tiff2rgba small\\_file"
set yrange [ * : * ]
set ytics 1e+05
plot "./stats_instructions_libtiffID0.txt" using 2:xtic(1), '' using 3