#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include "vm.h"
#include "corpus.h"

using namespace std;

void print_stats(const Stats& stats) {
	chrono::duration<double> elapsed;
	chrono::steady_clock::time_point start = chrono::steady_clock::now();
	uint64_t cases;
	double fcps, run_time, reset_time, reset1_time, reset2_time, reset3_time,
	       syscall_time, kvm_time, mut_time, vm_exits, vm_exits_sys,
		   vm_exits_debug, vm_exits_cov, reset_pages;
	while (true) {
		this_thread::sleep_for(chrono::seconds(1));
		elapsed        = chrono::steady_clock::now() - start;
		cases          = stats.cases;
		fcps           = (double)cases / elapsed.count();
		run_time       = (double)stats.run_cycles / stats.total_cycles;
		reset_time     = (double)stats.reset_cycles / stats.total_cycles;
		reset1_time    = (double)stats.reset1_cycles / stats.total_cycles;
		reset2_time    = (double)stats.reset2_cycles / stats.total_cycles;
		reset3_time    = (double)stats.reset3_cycles / stats.total_cycles;
		syscall_time   = (double)stats.syscall_cycles / stats.total_cycles;
		kvm_time       = (double)stats.kvm_cycles / stats.total_cycles;
		mut_time       = (double)stats.mut_cycles / stats.total_cycles;
		reset_pages    = (double)stats.reset_pages / stats.cases;
		vm_exits       = (double)stats.vm_exits / stats.cases;
		vm_exits_sys   = (double)stats.vm_exits_sys / stats.cases;
		vm_exits_debug = (double)stats.vm_exits_debug / stats.cases;
		vm_exits_cov   = (double)stats.vm_exits_cov / stats.cases;
		printf("cases: %lu, fcps: %.3f, vm exits: %.3f\n",
		       cases, fcps, vm_exits);

		if (TIMETRACE >= 1)
			printf("\trun: %.3f, reset: %.3f, mut: %.3f\n",
			       run_time, reset_time, mut_time);

		if (TIMETRACE >= 2) {
			printf("\treset1: %.3f, reset2: %.3f, reset3: %.3f, syscall: %.3f"
			       ", kvm: %.3f, pages: %.3f\n",
			       reset1_time, reset2_time, reset3_time, syscall_time,
				   kvm_time, reset_pages);
			printf("\tvm exits sys: %.3f, vm exits debug: %.3f, vm exits cov: "
			       "%.3f\n",
					vm_exits_sys, vm_exits_debug, vm_exits_cov);
		}
	}
}

void worker(int id, const Vm& base, Corpus& corpus, Stats& stats) {
	// The vm we'll be running
	Vm runner(base);

	// Custom RNG: avoids locks and it's simpler
	Rng rng;

	// Timetracing
	cycle_t cycles_init, cycles;

	while (true) {
		Stats local_stats;
		cycles_init = _rdtsc();

		// Run some time saving stats locally
		while (_rdtsc() - cycles_init < 50000000) {
			// Get new input
			cycles = rdtsc1();
			/* const string& input = corpus.get_new_input(id, rng);
			runner.set_file("test", input); */
			local_stats.mut_cycles += rdtsc1() - cycles;

			// Perform run
			cycles = rdtsc1();
			runner.run(local_stats);
			local_stats.cases++;
			local_stats.run_cycles += rdtsc1() - cycles;

			// Reset vm
			cycles = rdtsc1();
			runner.reset(base, local_stats);
			local_stats.reset_cycles += rdtsc1() - cycles;
		}
		local_stats.total_cycles = _rdtsc() - cycles_init;

		// Update global stats
		stats.update(local_stats);
	}
}

#define num_threads 8


int main(int argc, char** argv) {
	init_kvm();
	Stats stats;
	Corpus corpus(num_threads, "../corpus");
	Vm vm(
		8 * 1024 * 1024,
		"./kernel/kernel",
		"../test_bins/readelf",
		{"./readelf", "-l", "test"}
	);

	string file = read_file("./hypervisor/kvm-fuzz");
	vm.set_file("test", file);

	vm.init();

/* 	vm.run_until(0x401c80, stats); // readelf
	Vm runner(vm);
	runner.dump_regs();
	runner.run(stats);

	printf("\n\n\n");
	runner.reset(vm, stats);
	runner.run(stats);
	return 0 ; */

	vm.run_until(0x401c80, stats); // readelf
	//vm.run_until(0x402520, stats); // objdump

	// Create threads
	vector<thread> threads;
	for (int i = 0; i < num_threads; i++) {
		threads.push_back(thread(worker, i, ref(vm), ref(corpus), ref(stats)));
	}
	threads.push_back(thread(print_stats, ref(stats)));

	for (thread& t : threads)
		t.join();
	return 0;
}