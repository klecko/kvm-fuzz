#include <vector>
#include <unordered_set>
#include <string>
#include <atomic>
#include <stats.h>
#include "common.h"
#include "fault.h"

std::string read_file(const std::string& filepath);

// Used for mutating inputs. We don't use glibc rand() because it uses locks
// in order to be thread safe. Instead, we implement a simpler algorithm, and
// each thread will have its own rng.
class Rng {
	private:
		uint64_t state;
	public:
		Rng(){
			state = _rdtsc();
		}
		uint64_t rnd(){
			// xorshif64*
			state ^= state >> 12;
			state ^= state << 25;
			state ^= state >> 27;
			return state * 2685821657736338717LL;
		}
		uint64_t rnd(uint64_t min, uint64_t max){
			ASSERT(max >= min, "rnd bad range: %lu, %lu", min, max);
			return min + (rnd() % (max-min+1));
		}
		uint64_t rnd_exp(uint64_t min, uint64_t max){
			uint64_t x = rnd(min, max);
			return rnd(min, x);
		}
};


class Corpus {
public:
	static const int MIN_MUTATIONS = 1;
	static const int MAX_MUTATIONS = 5;

	Corpus(int nthreads, const std::string& folder);

	size_t size() const;
	size_t memsize() const;
	size_t max_input_size() const;
	size_t unique_crashes() const;

	// Get a new mutated input, which will be a constant reference to
	// `mutated_inputs[id]
	const std::string& get_new_input(int id, Rng& rng, Stats& stats);

	// Report a new crash
	void report_crash(int id, const FaultInfo& fault);

private:
	// Corpus and its lock
	std::vector<std::string> m_corpus;
	std::atomic_flag m_lock_corpus;

	// Unique crashes and its lock
	std::unordered_set<FaultInfo> m_crashes;
	std::atomic_flag m_lock_crashes;

	// Vector with one mutated input for each thread. No need to lock
	std::vector<std::string> m_mutated_inputs;

	// Max input size, used in expand mutation
	size_t m_max_input_size;

	// Add input to corpus
	void add_input(const std::string& new_input);

	// Mutate input in `mutated_inputs[id]`
	void mutate_input(int id, Rng& rng);

	// Mutation strategies
	typedef void (Corpus::*mutation_strat_t)(std::string& input, Rng& rng);
	static const std::vector<mutation_strat_t> mut_strats;
	void shrink(std::string& input, Rng& rng);
	void expand(std::string& input, Rng& rng);
	void bit(std::string& input, Rng& rng);
	void dec_byte(std::string& input, Rng& rng);
	void inc_byte(std::string& input, Rng& rng);
	void neg_byte(std::string& input, Rng& rng);
	void add_sub(std::string& input, Rng& rng);
	void set(std::string& input, Rng& rng);
	void swap(std::string& input, Rng& rng);
	void copy(std::string& input, Rng& rng);
	void inter_splice(std::string& input, Rng& rng);
	void insert_rand(std::string& input, Rng& rng);
	void overwrite_rand(std::string& input, Rng& rng);
	void byte_repeat_overwrite(std::string& input, Rng& rng);
	void byte_repeat_insert(std::string& input, Rng& rng);
	void magic_overwrite(std::string& input, Rng& rng);
	void magic_insert(std::string& input, Rng& rng);
	void random_overwrite(std::string& input, Rng& rng);
	void random_insert(std::string& input, Rng& rng);
	void splice_overwrite(std::string& input, Rng& rng);
	void splice_insert(std::string& input, Rng& rng);
};