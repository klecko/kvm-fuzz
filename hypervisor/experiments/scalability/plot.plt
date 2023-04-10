#!/usr/bin/env -S gnuplot -p
set grid
set title "Propiedades de escalado"
set ylabel "Aceleración"
set xlabel "Cores"

# aflpp: empty
# kvmfuzz: readelf -l
first_val_aflpp=system("awk 'FNR == 1 {print $2}' ./hypervisor/experiments/scalability/output_aflpp")
first_val_kvmfuzz=system("awk 'FNR == 1 {print $2}' ./hypervisor/experiments/scalability/output_kvmfuzz")

plot "./hypervisor/experiments/scalability/output_kvmfuzz" using ($1):($2/first_val_kvmfuzz) with lines title "kvm-fuzz", \
     "./hypervisor/experiments/scalability/output_aflpp" using ($1):($2/first_val_aflpp) with lines title "AFL++"

set terminal pdfcairo enhanced color notransparent
set output './hypervisor/experiments/scalability/scalability.pdf'
replot

set terminal qt 1 noraise enhanced
pause mouse close


# while (1) {
# 	replot
# 	pause 1
# }
