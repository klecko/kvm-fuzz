#!/usr/bin/env gnuplot

set title "Rendimiento del mecanismo de snapshots"
set grid

set xlabel "Páginas modificadas"
set ylabel "Ejecuciones por segundo"
set logscale x
set logscale y

plot "./hypervisor/experiments/resets/output_kvmfuzz" using 1:2 with lines title "kvm-fuzz", \
     "./hypervisor/experiments/resets/output_nyx" using 1:2 with lines title "Nyx", \
     "./hypervisor/experiments/resets/output_aflpp" using 1:2 with lines title "AFL++"

set terminal pdfcairo enhanced color notransparent
set output './hypervisor/experiments/resets/resets.pdf'
replot

set terminal qt 1 noraise enhanced
pause mouse close

# while (1) {
# 	replot
# 	pause 1
# }
