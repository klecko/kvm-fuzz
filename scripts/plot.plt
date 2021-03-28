#!/usr/bin/env gnuplot
set title "Test kvm-fuzz"
set xlabel "Time (seconds)"
set grid
set multiplot layout 1,2

set ylabel "Fuzz cases per second"
plot "./stats.txt" using 1:2 with lines title "fcps"

set ylabel "Coverage"
plot "./stats.txt" using 1:3 with lines title "cov"

pause 1
reread
# while (1) {
# 	replot
# 	pause 1
# }
