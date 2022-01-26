#include <vector>
#include <set>
#include <unordered_set>
#include <string>
#include <atomic>
#include <stats.h>
#include "common.h"
#include "fault.h"
#include "vm.h"
#include "coverage.h"
#include "files.h"
#include "rng.h"

class Corpus {
public:
	static const int MIN_MUTATIONS = 1;
	static const int MAX_MUTATIONS = 10;
	static constexpr const char* CORPUS_DIR      = "corpus";
	static constexpr const char* CRASHES_DIR     = "crashes";
	static constexpr const char* MIN_CORPUS_DIR  = "minimized_corpus";
	static constexpr const char* MIN_CRASHES_DIR = "minimized_crashes";

	Corpus(int nthreads, const std::string& input, const std::string& output);

	// Trivial getters
	size_t size() const;
	size_t memsize() const;
	size_t max_input_size() const;
	size_t unique_crashes() const;
	size_t coverage() const;
	std::string seed_filename(size_t i) const;
	FileRef element(size_t i) const;

	// Set mode. This must be called before doing anything else. Normal mode
	// requires the total coverage of the seed corpus, while minimization
	// modes require the coverage or fault associated to each seed input.
	void set_mode_normal(const Coverage& total_coverage);
	void set_mode_corpus_min(const std::vector<Coverage>& coverages);
	void set_mode_crashes_min(const std::vector<FaultInfo>& faults);

	// Get a new mutated input, which will be a constant reference to
	// `mutated_inputs[id]`
	FileRef get_new_input(int id, Rng& rng, Stats& stats);

	// Report a new crash on a given vm
	void report_crash(int id, Vm& vm);

	// Report coverage of a run
	void report_coverage(int id, const Coverage& cov);

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

	// Recorded coverage in all runs
	SharedCoverage m_recorded_coverage;

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
	std::vector<Coverage> m_coverages;

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
	void handle_cov_corpus_minimization(int id, const Coverage& cov);

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