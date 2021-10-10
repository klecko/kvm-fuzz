#!/usr/bin/env -S gnuplot -p
set grid
set title "Fuzz cases per second vs cores"
set ylabel "Fuzz cases per second"
set xlabel "Cores"
plot "./stats.txt" with lines title "fcps"

# while (1) {
# 	replot
# 	pause 1
# }
