#include <vector>
#include <set>
#include <unordered_set>
#include <string>
#include <atomic>
#include <stats.h>
#include "common.h"
#include "fault.h"

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
	static const int MAX_MUTATIONS = 10;

	Corpus(int nthreads, const std::string& input, const std::string& output);

	// Trivial getters
	size_t size() const;
	size_t memsize() const;
	size_t max_input_size() const;
	size_t unique_crashes() const;
	size_t coverage() const;
	std::string seed_filename(size_t i) const;
	const std::string& element(size_t i) const;

	// Set mode. This must be called before doing anything else. Normal mode
	// requires the total coverage of the seed corpus, while minimization
	// modes require the coverage or fault associated to each seed input.
	void set_mode_normal(const std::set<vaddr_t>& total_coverage);
	void set_mode_corpus_min(const std::vector<std::set<vaddr_t>>& coverages);
	void set_mode_crashes_min(const std::vector<FaultInfo>& faults);

	// Get a new mutated input, which will be a constant reference to
	// `mutated_inputs[id]`
	const std::string& get_new_input(int id, Rng& rng, Stats& stats);

	// Report a new crash
	void report_crash(int id, const FaultInfo& fault);

#ifdef ENABLE_COVERAGE_INTEL_PT
	void report_coverage(int id, uint8_t* cov);
#endif
#ifdef ENABLE_COVERAGE_BREAKPOINTS
	void report_coverage(int id, const std::set<vaddr_t>& new_blocks);
#endif

private:
	enum Mode {
		Normal,
		CorpusMinimization,
		CrashesMinimization,
		Unknown
	};

	// Directories
	std::string m_input_dir;
	std::string m_output_dir_corpus;
	std::string m_output_dir_crashes;
	std::string m_output_dir_min_corpus;
	std::string m_output_dir_min_crashes;

	// Corpus and its lock
	std::vector<std::string> m_corpus;
	std::atomic_flag m_lock_corpus;

	// Unique crashes and its lock
	std::unordered_set<FaultInfo> m_crashes;
	std::atomic_flag m_lock_crashes;

	// Vector with one mutated input for each thread. No need to lock
	std::vector<std::string> m_mutated_inputs;

#ifdef ENABLE_COVERAGE_INTEL_PT
	// Bitmap of recorded coverage
	uint8_t* m_recorded_cov_bitmap;
	std::atomic<size_t> m_recorded_cov;
#endif

#ifdef ENABLE_COVERAGE_BREAKPOINTS
	std::atomic_flag m_lock_basic_blocks_hits;
	std::unordered_set<vaddr_t> m_basic_blocks_hit;
#endif

	// Max input size, used in expand mutation
	size_t m_max_input_size;

	// Filenames of initial corpus elements (seeds)
	std::vector<std::string> m_seeds_filenames;

	// Position i holds index in `m_corpus` of the input that
	// `m_mutated_inputs[i]` was mutated from
	std::vector<size_t> m_mutated_inputs_indexes;

	// Current mode
	Mode m_mode;

	// Coverage of each of the seeds, when in mode CorpusMinimization
	std::vector<std::set<vaddr_t>> m_coverages;

	// Fault of each of the seeds, when in mode FaultMinimization
	std::vector<FaultInfo> m_faults;


	// Add input to corpus and write it to corpus dir
	void add_input(const std::string& new_input);

	// Mutate input in `mutated_inputs[id]`
	void mutate_input(int id, Rng& rng);

	// Check if last mutation reduced the file size while keeping the fault/cov
	// the same. In that case, replace associated input in the corpus with
	// the reduced one, and write it to its corresponding dir.
	void handle_crash_crashes_minimization(int id, const FaultInfo& fault);
	void handle_cov_corpus_minimization(int id, const std::set<vaddr_t>& cov);

	// Apply afl-cmin algorithm to reduce number of elements in the corpus
	void minimize();

	// Define the filename of corpus elements, minimized corpus elements and
	// minimized crashes saved to disk. Crash filenames are the description
	// given by FaultInfo.
	std::string corpus_filename(size_t i);
	std::string min_corpus_filename(size_t i);
	std::string min_crash_filename(size_t i);

	// Write `m_corpus[i]` to corresponding output directory. Crash files option
	// is overloaded so we can get it from `m_mutated_inputs[id]` in case we
	// decide not to add crash files to corpus.
	void write_corpus_file(size_t i);
	void write_crash_file(int id, const FaultInfo& fault);
	void write_crash_file(size_t i, const FaultInfo& fault);
	void write_min_corpus_file(size_t i);
	void write_min_crash_file(size_t i);

	// Mutation strategies
	typedef void (Corpus::*mutation_strat_t)(std::string& input, Rng& rng);
	static const std::vector<mutation_strat_t> mut_strats;
	static const std::vector<mutation_strat_t> mut_strats_reduce;
	void mut_shrink(std::string& input, Rng& rng);
	void mut_expand(std::string& input, Rng& rng);
	void mut_bit(std::string& input, Rng& rng);
	void mut_dec_byte(std::string& input, Rng& rng);
	void mut_inc_byte(std::string& input, Rng& rng);
	void mut_neg_byte(std::string& input, Rng& rng);
	void mut_add_sub(std::string& input, Rng& rng);
	void mut_set(std::string& input, Rng& rng);
	void mut_swap(std::string& input, Rng& rng);
	void mut_copy(std::string& input, Rng& rng);
	void mut_inter_splice(std::string& input, Rng& rng);
	void mut_insert_rand(std::string& input, Rng& rng);
	void mut_overwrite_rand(std::string& input, Rng& rng);
	void mut_byte_repeat_overwrite(std::string& input, Rng& rng);
	void mut_byte_repeat_insert(std::string& input, Rng& rng);
	void mut_magic_overwrite(std::string& input, Rng& rng);
	void mut_magic_insert(std::string& input, Rng& rng);
	void mut_random_overwrite(std::string& input, Rng& rng);
	void mut_random_insert(std::string& input, Rng& rng);
	void mut_splice_overwrite(std::string& input, Rng& rng);
	void mut_splice_insert(std::string& input, Rng& rng);
};