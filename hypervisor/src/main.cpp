#include <iostream>
#include <fstream>
#include <thread>
#include <cstring>
#include "vm.h"
#include "corpus.h"
#include "args.h"
#include "utils.h"

using namespace std;

void print_stats(const Stats& stats, const Corpus& corpus) {
	const chrono::milliseconds REFRESH_TIME {1000};
	chrono::duration<double> elapsed, elapsed_total, no_new_cov_time;
	chrono::steady_clock::time_point start = chrono::steady_clock::now(),
		new_cov_last_time = start;
	uint64_t cycles_elapsed, cases_elapsed, cases, cov, cov_old = 0, corpus_n,
	         crashes, unique_crashes, timeouts;
	double mips, fcps, run_time, reset_time, hypercall_time, corpus_mem,
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
		timeouts        = stats.timeouts;
		fcps            = (double)cases_elapsed / elapsed.count();
		mips            = (double)(stats.instr - stats_old.instr) / (elapsed.count() * 1000000);
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
		printf("[%.3f] cases: %lu, mips: %.3f, fcps: %.3f, cov: %lu, "
		       "corpus: %lu/%.3fKB, unique crashes: %lu (total: %lu), "
		       "timeouts: %lu, no new cov for: %.3f\n",
		       elapsed_total.count(), cases, mips, fcps, cov, corpus_n,
		       corpus_mem, unique_crashes, crashes, timeouts,
		       no_new_cov_time.count());
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

void set_input(Vm& vm, FileRef input) {
	// Set input as a file which the guest will open and read, making sure
	// the kernel has already submitted a buffer so the input is copied to its
	// memory.
	vm.set_file("input", input, Vm::CheckCopied::Yes);

	// If our target received the input in a buffer instead of using open and
	// read, we may want to write it to the guest memory, instead of using
	// memory-loaded files. Assuming vm is at the entry of a function that takes
	// as parameters the buffer pointer, the input length and the buffer length:
	// size_t input_size = min((size_t)vm.regs().rdx, input.length);
	// vm.mmu().write_mem(vm.regs().rdi, input.ptr, input_size);
	// vm.regs().rsi = input_size;
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
			FileRef input = corpus.get_new_input(id, rng, local_stats);
			local_stats.mut_cycles += rdtsc1() - cycles;

			// Update input
			cycles = rdtsc1();
			set_input(runner, input);
			local_stats.set_input_cycles += rdtsc1() - cycles;

			// Perform run
			cycles = rdtsc1();
			reason = runner.run(local_stats);
			local_stats.run_cycles += rdtsc1() - cycles;
			local_stats.cases++;
			local_stats.instr += runner.instructions_executed_last_run();

			// Check RunEndReason
			switch (reason) {
				case Vm::RunEndReason::Breakpoint:
				case Vm::RunEndReason::Exit:
					break;
				case Vm::RunEndReason::Timeout:
					local_stats.timeouts++;
					break;
				case Vm::RunEndReason::Crash:
					local_stats.crashes++;
					corpus.report_crash(id, runner);
					break;
				default:
					die("unexpected RunEndReason: %s\n", Vm::reason_str(reason));
			}

			// Report coverage
			cycles = rdtsc1();
			corpus.report_coverage(id, runner.coverage());
			runner.reset_coverage();
			local_stats.report_cov_cycles += rdtsc1() - cycles;

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


int main(int argc, char** argv) {
	Args args;
	if (!args.parse(argc, argv))
		return 0;

	setvbuf(stdout, nullptr, _IONBF, 0);
	setvbuf(stderr, nullptr, _IONBF, 0);
	cout << "Number of threads: " << args.jobs << endl;
	Stats stats;
	Corpus corpus(args.jobs, args.input_dir, args.output_dir);
	Vm vm(
		args.memory,
		args.kernel_path,
		args.binary_path,
		args.binary_argv
	);

	// Set initial file, except if we are doing a single run with no input
	// file. If we are not doing a single run, the initial file is a dummy
	// string which will be replaced in the fuzz loop with inputs provided by
	// the corpus. We set its size to the maximum input size so kernel allocates
	// a buffer of that size.
	// Note this is not needed if we are using input injection in set_input
	// instead of memory-loaded files.
	string file;
	if (!(args.single_run && args.single_run_input_path.empty())) {
		if (args.single_run) {
			file = utils::read_file(args.single_run_input_path);
		} else {
			file = string(corpus.max_input_size(), 'a');
		}
		vm.set_file("input", FileRef::from_string(file));
	}

	// Other memory-loaded files should be set here as well
	for (const string& path : args.memory_files) {
		vm.read_and_set_shared_file(path);
	}

	// Run until main or elf entry point before forking or running single input
	vaddr_t fork_addr = vm.elf().resolve_symbol("main");
	if (!fork_addr)
		fork_addr = vm.elf().entry();
	vm.run_until(fork_addr, stats);

	// Optionally set breakpoints to end the run before the syscall `exit` is
	// called. Setting a breakpoint at libc function `exit` avoids running exit
	// handlers, improving performance.
	vaddr_t exit_addr = vm.elf().resolve_symbol("exit");
	if (exit_addr)
		vm.set_breakpoint(exit_addr);

	// Reset timer so it starts counting from 0, and set specified timeout
	vm.reset_timer();
	vm.set_timeout(args.timeout);

	// We do this here because we need libraries to be already loaded in case
	// we want to put breakpoints to get code coverage in those areas.
	vm.setup_coverage();

	if (args.single_run) {
		// Just perform a single run and exit.
		if (args.single_run_input_path.empty()) {
			printf("Performing single run with no input file\n");
		} else {
			printf("Performing single run with input file '%s', length %lu\n",
			       args.single_run_input_path.c_str(), file.size());
			set_input(vm, FileRef::from_string(file));
		}
		Vm::RunEndReason reason = vm.run(stats);
		if (reason == Vm::RunEndReason::Crash)
			vm.print_fault_info();
		printf("Run ended with reason %s\n", Vm::reason_str(reason));
		// vm.dump("libtiff-data");
		return 0;
	}

	printf("Performing first runs...\n");
	if (args.minimize_corpus) {
#ifndef ENABLE_COVERAGE
		printf("we can't minimize corpus without coverage\n");
		return 0;
#else
		// Ask for breakpoints to dirty memory, so they are resetted after
		// each run, as we want to get the full coverage and not just new
		// basic block hits.
		vm.set_breakpoints_dirty(true);

		// Get coverage of every input and submit it to corpus
		vector<Coverage> coverages;
		Vm runner(vm);
		Vm::RunEndReason reason;
		for (size_t i = 0; i < corpus.size(); i++) {
			set_input(runner, corpus.element(i));
			reason = runner.run(stats);
			switch (reason) {
				case Vm::RunEndReason::Breakpoint:
				case Vm::RunEndReason::Exit:
					break;
				case Vm::RunEndReason::Crash:
					vm.print_fault_info();
					die("Input file '%s' crashed in corpus minimization mode\n",
					    corpus.seed_filename(i).c_str());
				default:
					die("unexpected RunEndReason for input '%s': %s\n",
					    corpus.seed_filename(i).c_str(), Vm::reason_str(reason));
			}
			coverages.push_back(runner.coverage());
			runner.reset_coverage();
			runner.reset(vm, stats);
		}
		corpus.set_mode_corpus_min(coverages);
#endif

	} else if (args.minimize_crashes) {
		// Make sure every input actually crashes, and submit faults to corpus
		vector<FaultInfo> faults;
		Vm runner(vm);
		Vm::RunEndReason reason;
		for (size_t i = 0; i < corpus.size(); i++) {
			set_input(runner, corpus.element(i));
			reason = runner.run(stats);
			ASSERT(reason == Vm::RunEndReason::Crash, "input '%s' didn't crash",
			       corpus.seed_filename(i).c_str());
			faults.push_back(runner.fault());
			runner.reset(vm, stats);
		}
		corpus.set_mode_crashes_min(faults);

	} else {
		// Perform run with each seed input and submit total coverage to corpus
		Vm runner(vm);
		for (size_t i = 0; i < corpus.size(); i++) {
			set_input(runner, corpus.element(i));
			runner.run(stats);
			runner.reset(vm, stats);
		}
		corpus.set_mode_normal(runner.coverage());
	}


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
