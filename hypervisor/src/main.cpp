#include <iostream>
#include <fstream>
#include <thread>
#include <cstring>
#include "vm.h"
#include "corpus.h"
#include "args.h"

using namespace std;

void print_stats(const Stats& stats, const Corpus& corpus) {
	const chrono::milliseconds REFRESH_TIME {1000};
	chrono::duration<double> elapsed, elapsed_total, no_new_cov_time;
	chrono::steady_clock::time_point start = chrono::steady_clock::now(),
		new_cov_last_time = start;
	uint64_t cycles_elapsed, cases_elapsed, cases, cov, cov_old = 0, corpus_n,
	         crashes, unique_crashes;
	double fcps, run_time, reset_time, hypercall_time, corpus_mem,
	       kvm_time, mut_time, mut1_time, mut2_time, set_input_time,
	       reset_pages, vm_exits, vm_exits_hc, update_cov_time, report_cov_time,
	       vm_exits_debug, vm_exits_cov;
	ofstream os("stats.txt");
	while (true) {
		Stats stats_old = stats;
		this_thread::sleep_for(REFRESH_TIME);
		auto now        = chrono::steady_clock::now();
		elapsed         = now - start - elapsed_total;
		elapsed_total   = now - start;
		cases           = stats.cases;
		cases_elapsed   = stats.cases - stats_old.cases;
		cycles_elapsed  = stats.total_cycles - stats_old.total_cycles;
		cov             = corpus.coverage();
		corpus_n        = corpus.size();
		corpus_mem      = (double)corpus.memsize() / 1024;
		crashes         = stats.crashes;
		unique_crashes  = corpus.unique_crashes();
		fcps            = (double)cases_elapsed / elapsed.count();
		vm_exits        = (double)(stats.vm_exits - stats_old.vm_exits) / cases_elapsed;
		vm_exits_hc     = (double)(stats.vm_exits_hc - stats_old.vm_exits_hc) / cases_elapsed;
		vm_exits_cov    = (double)(stats.vm_exits_cov - stats_old.vm_exits_cov) / cases_elapsed;
		vm_exits_debug  = (double)(stats.vm_exits_debug - stats_old.vm_exits_debug) / cases_elapsed;
		reset_pages     = (double)(stats.reset_pages - stats_old.reset_pages) / cases_elapsed;
		run_time        = (double)(stats.run_cycles - stats_old.run_cycles) / cycles_elapsed;
		reset_time      = (double)(stats.reset_cycles - stats_old.reset_cycles) / cycles_elapsed;
		mut_time        = (double)(stats.mut_cycles - stats_old.mut_cycles) / cycles_elapsed;
		set_input_time  = (double)(stats.set_input_cycles - stats_old.set_input_cycles) / cycles_elapsed;
		kvm_time        = (double)(stats.kvm_cycles - stats_old.kvm_cycles) / cycles_elapsed;
		hypercall_time  = (double)(stats.hypercall_cycles - stats_old.hypercall_cycles) / cycles_elapsed;
		mut1_time       = (double)(stats.mut1_cycles - stats_old.mut1_cycles) / cycles_elapsed;
		mut2_time       = (double)(stats.mut2_cycles - stats_old.mut2_cycles) / cycles_elapsed;
		update_cov_time = (double)(stats.update_cov_cycles - stats_old.update_cov_cycles) / cycles_elapsed;
		report_cov_time = (double)(stats.report_cov_cycles - stats_old.report_cov_cycles) / cycles_elapsed;
		if (cov != cov_old)
			new_cov_last_time = now;
		cov_old         = cov;
		no_new_cov_time = now - new_cov_last_time;

		// Clear screen
		//printf("\x1B[2J\x1B[H");

		// Free stats (no rdtsc)
		printf("[%.3f] cases: %lu, fcps: %.3f, cov: %lu, corpus: %lu/%.3fKB, "
		       "unique crashes: %lu (total: %lu), no new cov for: %.3f\n",
		       elapsed_total.count(), cases, fcps, cov, corpus_n, corpus_mem,
		       unique_crashes, crashes, no_new_cov_time.count());
		printf("\tvm exits: %.3f (hc: %.3f, cov: %.3f, debug: %.3f), "
		       "reset pages: %.3f\n",
		       vm_exits, vm_exits_hc, vm_exits_cov, vm_exits_debug,
		       reset_pages);

		if (TIMETRACE >= 1)
			printf("\trun: %.3f, reset: %.3f, mut: %.3f, set_input: %.3f, "
			       "report_cov: %.3f\n",
			       run_time, reset_time, mut_time, set_input_time,
			       report_cov_time);

		if (TIMETRACE >= 2) {
			printf("\tkvm: %.3f, hc: %.3f, update_cov: %.3f, mut1: %.3f, "
			       "mut2: %.3f\n",
			       kvm_time, hypercall_time, update_cov_time, mut1_time,
			       mut2_time);
		}

		// Print stats to file
		os << elapsed_total.count() << " " << fcps << " " << cov << endl;
	}
}

void worker(int id, const Vm& base, Corpus& corpus, Stats& stats) {
	// The vm we'll be running
	Vm runner(base);

	// Custom RNG: avoids locks and it's simpler
	Rng rng;

	// Timetracing
	cycle_t cycles_init, cycles;

	Vm::RunEndReason reason;

	while (true) {
		Stats local_stats;
		cycles_init = _rdtsc();

		// Run some time saving stats locally
		while (_rdtsc() - cycles_init < 50000000) {
			// Get new input
			cycles = rdtsc1();
			const string& input = corpus.get_new_input(id, rng, stats);
			local_stats.mut_cycles += rdtsc1() - cycles;

			// Update input file. Make sure kernel has already submitted a
			// buffer so the input is being copied into its memory.
			// TODO: DON'T RESET THIS MEMORY AREA, maybe add other memory slot
			// for memory that we don't want to reset?
			cycles = rdtsc1();
			runner.set_file("input", input, true);

			// If our target received the input in a buffer instead of using
			// open & read, we may want to write it to the guest memory, instead
			// of using memory-loaded files.
			// Assuming rdi is buffer pointer, rsi is input length and rdx is
			// buffer length:
			// size_t input_size = min((size_t)runner.regs().rdx, input.size());
			// runner.mmu().write_mem(runner.regs().rdi, input.c_str(), input_size);
			// runner.regs().rsi = input_size;
			local_stats.set_input_cycles += rdtsc1() - cycles;

			// Perform run
			cycles = rdtsc1();
			reason = runner.run(local_stats);
			local_stats.cases++;
			local_stats.run_cycles += rdtsc1() - cycles;

			// Check RunEndReason
			if (reason == Vm::RunEndReason::Crash) {
				stats.crashes++;
				corpus.report_crash(id, runner.fault());
			} else if (reason != Vm::RunEndReason::Exit) {
				die("unexpected RunEndReason: %d\n", reason);
			}

#ifdef ENABLE_COVERAGE
			// Report coverage
			cycles = rdtsc1();
			corpus.report_coverage(id, runner.coverage());
			runner.reset_coverage();
			local_stats.report_cov_cycles += rdtsc1() - cycles;
#endif

			// Reset vm
			cycles = rdtsc1();
			runner.reset(base, local_stats);
			local_stats.reset_cycles += rdtsc1() - cycles;

			dbgprintf("run ended!\n\n");
		}
		local_stats.total_cycles = _rdtsc() - cycles_init;

		// Update global stats
		stats.update(local_stats);
	}
}

void read_and_set_file(const string& filename, Vm& vm) {
	static vector<string> file_contents;
	string content = read_file(filename);
	vm.set_file(filename, content);
	file_contents.push_back(move(content));
}

int main(int argc, char** argv) {
	Args args;
	if (!args.parse(argc, argv))
		return 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	cout << "Number of threads: " << args.jobs << endl;
	Stats stats;
	Corpus corpus(args.jobs, args.input_dir, args.output_dir);
	Vm vm(
		args.memory,
		args.kernel_path,
		args.binary_path,
		args.binary_argv,
		args.basic_blocks_path
	);

	// Virtual file, whose content will be provided by the corpus and will be
	// set before each run. We set its size to the maximum input size so kernel
	// allocs a buffer of that size.
	string file(corpus.max_input_size(), 'a');
	vm.set_file("input", file);

	// Other memory-loaded files should be set here as well
	for (const string& path : args.memory_files) {
		read_and_set_file(path, vm);
	}
	//read_and_set_file("/usr/lib/locale/locale-archive", vm);
	//read_and_set_file("/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", vm);

	// vm.set_breakpoint(vm.resolve_symbol("__free"), Vm::Breakpoint::Hook);
	// vm.set_breakpoint(vm.resolve_symbol("__libc_malloc"), Vm::Breakpoint::Hook);
	// vm.set_breakpoint(vm.resolve_symbol("__libc_memalign"), Vm::Breakpoint::Hook);
	// vm.set_breakpoint(vm.resolve_symbol("__libc_realloc"), Vm::Breakpoint::Hook);
	// vm.set_breakpoint(vm.resolve_symbol("__libc_calloc"), Vm::Breakpoint::Hook);
	// vm.set_breakpoint(vm.resolve_symbol("__libc_valloc"), Vm::Breakpoint::Hook);
	// vm.set_breakpoint(vm.resolve_symbol("__libc_pvalloc"), Vm::Breakpoint::Hook);

	if (!args.single_input_path.empty()) {
		// Just perform a single run and exit
		printf("Performing single run with input file '%s'\n",
		       args.single_input_path.c_str());
		string single_input(read_file(args.single_input_path));
		vm.set_file("input", single_input);
		Vm::RunEndReason reason = vm.run(stats);
		if (reason == Vm::RunEndReason::Crash)
			cout << vm.fault() << endl;
		printf("Run ended with reason %d\n", reason);
		return 0;
	}

	// Run until main before forking
	vm.run_until(vm.resolve_symbol("main"), stats);
	//vm.run_until(0x402319, stats); // readelf-static at fopen

	// Create threads and bind each one to a core
	printf("Creating threads...\n");
	cpu_set_t cpu;
	vector<thread> threads;
	for (int i = 0; i < args.jobs; i++) {
		thread t = thread(worker, i, ref(vm), ref(corpus), ref(stats));
		CPU_ZERO(&cpu);
		CPU_SET(i % thread::hardware_concurrency(), &cpu);
		int ret = pthread_setaffinity_np(t.native_handle(), sizeof(cpu), &cpu);
		ASSERT(ret == 0, "Binding thread to core %d: %s", i, strerror(ret));
		threads.push_back(move(t));
	}
	threads.push_back(thread(print_stats, ref(stats), ref(corpus)));

	for (thread& t : threads)
		t.join();
	return 0;
}