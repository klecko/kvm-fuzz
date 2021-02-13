#include <iostream>
#include <thread>
#include <x86intrin.h>
#include "vm.h"

using namespace std;

typedef unsigned long long cycle_t;

void print_stats(const uint64_t& cases) {
	chrono::duration<double> elapsed;
	chrono::steady_clock::time_point start = chrono::steady_clock::now();
	double fcps;
	while (true) {
		this_thread::sleep_for(chrono::seconds(1));
		elapsed = chrono::steady_clock::now() - start;
		fcps = (double)cases / elapsed.count();
		printf("cases: %lu, fcps: %.3f\n", cases, fcps);
	}
}

void worker(const Vm& base, uint64_t& cases) {
	Vm runner(base);
	uint64_t local_cases = 0;
	cycle_t cycles_init;
	while (true) {
		cycles_init = _rdtsc();

		// Run some time saving stats locally
		while (_rdtsc() - cycles_init < 50000000) {
			runner.run();
			runner.reset(base);
			local_cases++;
		}

		cases += local_cases;
		local_cases = 0;
	}
}

#define num_threads 8
int main(int argc, char** argv) {
	init_kvm();
	Vm vm(1024 * 1024, "../target", {"../target"});
	vm.run_until(0x401d35);

	// Create threads
	uint64_t cases = 0;
	vector<thread> threads;
	for (int i = 0; i < num_threads; i++) {
		threads.push_back(thread(worker, ref(vm), ref(cases)));
	}
	threads.push_back(thread(print_stats, ref(cases)));

	for (thread& t : threads)
		t.join();
	return 0;
}