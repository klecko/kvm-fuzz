#ifndef _STATS_H
#define _STATS_H

#include <cstdint>
#include <atomic>
#include <x86intrin.h> // _rdtsc()

/* Timetracing:
 *   - 0 means no timetracing
 *   - 1 means timetracing of things that happen once per fuzz case
 *   - 2 means timetracing of things that happen a lot of times per fuzz case.
 */
#define TIMETRACE 2

// Type returned by _rdtsc() for measuring cpu cycles
typedef unsigned long long cycle_t;

// STATS
struct Stats {
	uint64_t cases {0};
	uint64_t instr {0};
	uint64_t cov {0};
	uint64_t crashes {0};
	uint64_t timeouts {0};
	uint64_t ooms {0};
	cycle_t  total_cycles {0};
	cycle_t  reset_cycles {0};
	cycle_t  reset1_cycles {0};
	cycle_t  reset2_cycles {0};
	cycle_t  reset3_cycles {0};
	cycle_t  run_cycles {0};
	cycle_t  syscall_cycles {0};
	cycle_t  kvm_cycles {0};
	cycle_t  mut_cycles {0};
	std::atomic_flag lock = ATOMIC_FLAG_INIT;

	void update(const Stats& stats){
		while (lock.test_and_set());
		cases          += stats.cases;
		instr          += stats.instr;
		cov            += stats.cov;
		crashes        += stats.crashes;
		timeouts       += stats.timeouts;
		ooms           += stats.ooms;
		total_cycles   += stats.total_cycles;
		reset_cycles   += stats.reset_cycles;
		reset1_cycles  += stats.reset1_cycles;
		reset2_cycles  += stats.reset2_cycles;
		reset3_cycles  += stats.reset3_cycles;
		run_cycles     += stats.run_cycles;
		syscall_cycles += stats.syscall_cycles;
		kvm_cycles     += stats.kvm_cycles;
		mut_cycles     += stats.mut_cycles;
		lock.clear();
	}
};

#if TIMETRACE == 0
#define rdtsc1() (0)
#define rdtsc2() (0)

#elif TIMETRACE == 1
#define rdtsc1() _rdtsc()
#define rdtsc2() (0)

#elif TIMETRACE >= 2
#define rdtsc1() _rdtsc()
#define rdtsc2() _rdtsc()
#endif


#endif