#include <iostream>
#include <fstream>
#include <algorithm>
#include <dirent.h>
#include <sys/stat.h>
#include "corpus.h"
#include "magic_values.h"
#include "utils.h"

using namespace std;

Corpus::Corpus(int nthreads, const string& input_dir, const string& output_dir)
	: m_input_dir(input_dir)
	, m_output_dir_corpus(output_dir + "/" + CORPUS_DIR)
	, m_output_dir_crashes(output_dir + "/" + CRASHES_DIR)
	, m_output_dir_min_corpus(output_dir + "/" + MIN_CORPUS_DIR)
	, m_output_dir_min_crashes(output_dir + "/" + MIN_CRASHES_DIR)
	, m_lock_corpus(false)
	, m_lock_crashes(false)
	, m_mutated_inputs(nthreads)
	, m_mutated_inputs_indexes(nthreads)
	, m_mode(Mode::Unknown)
{
	// Reuse corpus as input
	if (m_input_dir == "-")
		m_input_dir = m_output_dir_corpus;

	// Try to open input directory
	DIR* dir = opendir(m_input_dir.c_str());
	ERROR_ON(!dir, "opening input directory %s", m_input_dir.c_str());

	// Iterate the directory
	struct dirent* ent;
	struct stat st;
	string filepath, input;
	size_t max_sz = 0;
	while ((ent = readdir(dir))){
		filepath = m_input_dir + "/" + ent->d_name;

		// Check file type. If readdir fails to provide it, fallback to stat
		if (ent->d_type == DT_UNKNOWN){
			stat(filepath.c_str(), &st);
			if (!S_ISREG(st.st_mode))
				continue;
		} else if (ent->d_type != DT_REG)
			continue;

		// For each regular file, add its content to the corpus and save
		// its filename
		input = read_file(filepath);
		m_corpus.push_back(input);
		m_seeds_filenames.push_back(ent->d_name);

		// Record the size of the largest initial file
		max_sz = max(max_sz, input.size());

		//cout << "Read file '" << ent->d_name << "', size: "
		//     << input.size() << endl;
	}
	closedir(dir);

	// Set max_input_size to X times the size of the largest initial file
	// This will be the maximum size of inputs produced by mutations
	m_max_input_size = 10*max_sz;

	// Set max_input_size to an absolute value
	//m_max_input_size = 200*1024;

	ASSERT(m_corpus.size() != 0, "empty corpus: %s", m_input_dir.c_str());
	cout << "Total files read: " << m_corpus.size() << endl;
	cout << "Max mutated input size: " << m_max_input_size << endl;

	// Create output directory (or do nothing if they existed).
	// Each mode we'll create the subdirectory they'll write their output to
	// here. Normal mode will write corpus and crashes dir, while each
	// minimization mode will write to its own directory.
	create_folder(output_dir);
}

size_t Corpus::size() const {
	return m_corpus.size();
}

size_t Corpus::memsize() const {
	size_t size = 0;
	for (const string& s : m_corpus)
		size += s.size();
	return size;
}

size_t Corpus::max_input_size() const {
	return m_max_input_size;
}

size_t Corpus::unique_crashes() const {
	return m_crashes.size();
}

size_t Corpus::coverage() const {
	return m_recorded_coverage.count();
}

string Corpus::seed_filename(size_t i) const {
	ASSERT(i < m_seeds_filenames.size(), "OOB i: %lu", i);
	return m_seeds_filenames[i];
}

FileRef Corpus::element(size_t i) const {
	ASSERT(i < m_corpus.size(), "OOB i: %lu", i);
	return FileRef::from_string(m_corpus[i]);
}

string Corpus::corpus_filename(size_t i) {
	return "id" + to_string(i);
}

string Corpus::min_corpus_filename(size_t i) {
	return seed_filename(i) + "_min";
}

string Corpus::min_crash_filename(size_t i) {
	return seed_filename(i) + "_min";
}

void Corpus::write_corpus_file(size_t i) {
	ASSERT(m_mode == Mode::Normal, "mode %d", m_mode);
	write_file(m_output_dir_corpus + "/" + corpus_filename(i), m_corpus[i]);
}

void Corpus::write_crash_file(size_t i, const FaultInfo& fault) {
	ASSERT(m_mode == Mode::Normal, "mode %d", m_mode);
	write_file(m_output_dir_crashes + "/" + fault.filename(), m_corpus[i]);
}

void Corpus::write_crash_file(int id, const FaultInfo& fault) {
	ASSERT(m_mode == Mode::Normal, "mode %d", m_mode);
	write_file(m_output_dir_crashes + "/" + fault.filename(),
	           m_mutated_inputs[id]);
}

void Corpus::write_min_corpus_file(size_t i) {
	ASSERT(m_mode == Mode::CorpusMinimization, "mode %d", m_mode);
	write_file(m_output_dir_min_corpus+ "/" + min_corpus_filename(i),
	           m_corpus[i]);
}

void Corpus::write_min_crash_file(size_t i) {
	ASSERT(m_mode == Mode::CrashesMinimization, "mode %d", m_mode);
	write_file(m_output_dir_min_crashes + "/" + min_crash_filename(i),
	           m_corpus[i]);
}

void Corpus::set_mode_normal(const Coverage& total_coverage) {
	ASSERT(m_mode == Mode::Unknown, "corpus mode already set to %d", m_mode);
	m_mode = Mode::Normal;
	m_recorded_coverage = total_coverage;
	cout << "Set corpus mode: Normal. Output directories will be "
	     << m_output_dir_corpus << " and " << m_output_dir_crashes
	     << ". Seed corpus coverage: " << coverage() << endl;

	// Create output folders. Write seed input files to disk only if corpus
	// directory is not the same as input directory, as we would just overwrite
	// current files with same content.
	create_folder(m_output_dir_corpus);
	create_folder(m_output_dir_crashes);
	if (m_output_dir_corpus != m_input_dir) {
		for (size_t i = 0; i < m_corpus.size(); i++) {
			write_corpus_file(i);
		}
	}
}

void Corpus::set_mode_corpus_min(const vector<Coverage>& coverages) {
#ifndef ENABLE_COVERAGE
	ASSERT(false, "corpus minimization mode needs coverage");
#endif
	ASSERT(m_mode == Mode::Unknown, "corpus mode already set to %d", m_mode);
	ASSERT(coverages.size() == m_corpus.size(), "size mismatch: %lu vs %lu",
	       coverages.size(), m_corpus.size());
	m_mode = Mode::CorpusMinimization;
	m_coverages = coverages;
	cout << "Set corpus mode: Corpus Minimization. Output directory will be "
	     << m_output_dir_min_corpus << endl;

	// Reduce number of elements using AFL algorithm before start trimming
	// the rest of the input files
	double old_size = size();
	double old_memsize = memsize();
	minimize();
	printf("reduced size by %.3f, memsize by %.3f\n",
	       (1 - (size() / old_size))*100, (1 - (memsize() / old_memsize))*100);

	// Create output folder and write seed input files to disk
	create_folder(m_output_dir_min_corpus);
	for (size_t i = 0; i < m_corpus.size(); i++) {
		write_min_corpus_file(i);
	}
}

void Corpus::set_mode_crashes_min(const vector<FaultInfo>& faults) {
	ASSERT(m_mode == Mode::Unknown, "corpus mode already set to %d", m_mode);
	ASSERT(faults.size() == m_corpus.size(), "size mismatch: %lu vs %lu",
	       faults.size(), m_corpus.size());
	m_mode = Mode::CrashesMinimization;
	m_faults = faults;
	cout << "Set corpus mode: Crashes Minimization. Output directory will be "
	     << m_output_dir_min_crashes << endl;

	// Create output folder and write seed input files to disk
	create_folder(m_output_dir_min_crashes);
	for (size_t i = 0; i < m_corpus.size(); i++) {
		write_min_crash_file(i);
	}
}

FileRef Corpus::get_new_input(int id, Rng& rng, Stats& stats){
	// Copy a random input to slot `id`, mutate it and return a
	// constant reference to it
	ASSERT(m_mode != Mode::Unknown, "mode not set");
	cycle_t cycles = rdtsc2();
	while (m_lock_corpus.test_and_set());
	size_t i = rng.rnd(0, m_corpus.size() - 1);
	m_mutated_inputs[id] = m_corpus[i];
	m_mutated_inputs_indexes[id] = i;
	m_lock_corpus.clear();
	stats.mut1_cycles += rdtsc2() - cycles;

	cycles = rdtsc2();
	mutate_input(id, rng);
	stats.mut2_cycles += rdtsc2() - cycles;
	return FileRef::from_string(m_mutated_inputs[id]);
}

void Corpus::report_crash(int id, Vm& vm) {
	ASSERT(m_mode != Mode::Unknown, "mode not set");

	const FaultInfo& fault = vm.fault();
	if (m_mode == Mode::CrashesMinimization) {
		handle_crash_crashes_minimization(id, fault);
		return;
	}

	// Try to insert fault information into our set
	while (m_lock_crashes.test_and_set());
	bool inserted = m_crashes.insert(fault).second;
	m_lock_crashes.clear();

	// If it was new, print fault information and dump input file to disk
	if (inserted) {
		vm.print_fault_info();

		// We still want to count unique crashes in corpus minimization mode,
		// but we don't want to write to other directories.
		if (m_mode != Mode::CorpusMinimization) {
			//add_input(m_mutated_inputs[id]);
			write_crash_file(id, fault);
		}
	}
}

void Corpus::handle_crash_crashes_minimization(int id, const FaultInfo& fault) {
	// If the fault is the same as the one we're trying to minimize and
	// the size of the mutated input is lower than current input size,
	// replace current input with mutated input and save file to disk.
	size_t i = m_mutated_inputs_indexes[id];
	if (fault == m_faults[i]) {
		const string& mutated_input = m_mutated_inputs[id];
		while (m_lock_corpus.test_and_set());
		if (mutated_input.size() < m_corpus[i].size()) {
			m_corpus[i] = mutated_input;
			write_min_crash_file(i);
		}
		m_lock_corpus.clear();
	}
}

void Corpus::report_coverage(int id, const Coverage& cov) {

	switch (m_mode) {
		case Mode::CrashesMinimization:
			break;
		case Mode::CorpusMinimization:
			handle_cov_corpus_minimization(id, cov);
			break;
		case Mode::Normal:
			if (m_recorded_coverage.add(cov)) {
				// There was new coverage
				add_input(m_mutated_inputs[id]);
			}
			break;
		case Mode::Unknown:
			ASSERT(false, "mode not set");
	}
}

void Corpus::handle_cov_corpus_minimization(int id, const Coverage& cov) {
	// If the coverage is the same and the size of the mutated input is
	// lower than current input size, replace current input with mutated
	// input and save file to disk.
	size_t i = m_mutated_inputs_indexes[id];
	if (cov == m_coverages[i]) {
		const string& mutated_input = m_mutated_inputs[id];
		while (m_lock_corpus.test_and_set());
		if (mutated_input.size() < m_corpus[i].size()) {
			m_corpus[i] = mutated_input;
			write_min_corpus_file(i);
		}
		m_lock_corpus.clear();
	}
}

void Corpus::minimize() {
#ifdef ENABLE_COVERAGE_BREAKPOINTS
	ASSERT(m_mode == Mode::CorpusMinimization, "mode %d", m_mode);
	ASSERT(m_coverages.size() == m_corpus.size(), "size mismatch: %lu vs %lu",
	       m_coverages.size(), m_corpus.size());

	// Calculate union of all coverages
	SharedCoverage missing_coverage;
	for (const Coverage& coverage : m_coverages) {
		missing_coverage.add(coverage);
	}

	// Afl-cmin algorithm
	std::vector<std::string> new_corpus;
	const size_t INVALID_INDEX = numeric_limits<size_t>::max();
	while (missing_coverage.count() > 0) {
		// 1. Find next basic block not yet in the temporary working set
		size_t missing = *missing_coverage.begin();

		// 2. Locate the winning corpus entry for this basic block, which is
		//    the smallest that covers it
		size_t i_winning = INVALID_INDEX;
		for (size_t i = 0; i < m_coverages.size(); i++) {
			if (!m_coverages[i].contains(missing))
				continue;
			bool is_better = m_corpus[i].size() < m_corpus[i_winning].size();
			if (is_better || i_winning == INVALID_INDEX)
				i_winning = i;
		}
		ASSERT(i_winning != INVALID_INDEX, "there's no input that covers bb?");
		new_corpus.push_back(m_corpus[i_winning]);

		// 3. Register all basic blocks reached by the winning entry
		for (vaddr_t bb_reached : m_coverages[i_winning]) {
			missing_coverage.remove(bb_reached);
		}
	}

	m_corpus = new_corpus;
#else
	// TODO maybe
#endif
}


void Corpus::add_input(const string& new_input){
	ASSERT(m_mode == Mode::Normal, "adding input to corpus in mode %d", m_mode);
	while (m_lock_corpus.test_and_set());
	size_t i = m_corpus.size();
	m_corpus.push_back(new_input);
	m_lock_corpus.clear();
	write_corpus_file(i);
}

// MUTATION STUFF
// I don't remember a shit about this code and I'm not gonna bother reading it
const vector<Corpus::mutation_strat_t> Corpus::mut_strats = {
	&Corpus::mut_shrink,
	&Corpus::mut_expand,
	&Corpus::mut_bit,
	&Corpus::mut_dec_byte,
	&Corpus::mut_inc_byte,
	&Corpus::mut_neg_byte,
	&Corpus::mut_add_sub,
	&Corpus::mut_set,
	&Corpus::mut_swap,
	&Corpus::mut_copy,
	&Corpus::mut_inter_splice,
	&Corpus::mut_insert_rand,
	&Corpus::mut_overwrite_rand,
	&Corpus::mut_byte_repeat_overwrite,
	&Corpus::mut_byte_repeat_insert,
	&Corpus::mut_magic_overwrite,
	&Corpus::mut_magic_insert,
	&Corpus::mut_random_overwrite,
	&Corpus::mut_random_insert,
	&Corpus::mut_splice_overwrite,
	&Corpus::mut_splice_insert,
};

const vector<Corpus::mutation_strat_t> Corpus::mut_strats_reduce = {
	&Corpus::mut_shrink,
	&Corpus::mut_bit,
	&Corpus::mut_dec_byte,
	&Corpus::mut_inc_byte,
	&Corpus::mut_neg_byte,
	&Corpus::mut_add_sub,
	&Corpus::mut_set,
	&Corpus::mut_swap,
	&Corpus::mut_copy,
};

void Corpus::mutate_input(int id, Rng& rng){
	static_assert(MIN_MUTATIONS <= MAX_MUTATIONS, "invalid range");
	static_assert(MAX_MUTATIONS != 0, "MAX_MUTATIONS must be positive. To "
	              "disable mutations undef ENABLE_MUTATIONS instead.");
#ifndef ENABLE_MUTATIONS
	return;
#endif

	string& input = m_mutated_inputs[id];
	size_t n_muts = rng.rnd(MIN_MUTATIONS, MAX_MUTATIONS);
	mutation_strat_t mut_strat;
	if (m_mode == Mode::Normal) {
		for (size_t i = 0; i < n_muts; i++){
			mut_strat = mut_strats[rng.rnd(0, mut_strats.size()-1)];
			(this->*mut_strat)(input, rng);
		}
		ASSERT(input.size() <= m_max_input_size, "mutation too large: %ld/%ld",
		       input.size(), m_max_input_size);
	} else {
		// We're in a minimization mode. Get mutation strategies from
		// mut_strats_reduce instead, and make sure we apply shrink at
		// least once
		size_t j, i_mut_shrink = rng.rnd(0, n_muts - 1);
		for (size_t i = 0; i < n_muts; i++) {
			if (i == i_mut_shrink) {
				mut_shrink(input, rng);
			} else {
				j = rng.rnd(0, mut_strats_reduce.size()-1);
				mut_strat = mut_strats_reduce[j];
				(this->*mut_strat)(input, rng);
			}
		}
	}
}

/* POR QUÉ AL INSERTAR COGE EL TAMAÑO COMO SI FUERA A OVERWRITEAR?
   ESO HACE QUE EL TAMAÑO DE LO QUE INSERTAS SEA MÁS PEQUEÑO CONFORME MÁS
   CERCA DEL FINAL LO INSERTES */

size_t rand_offset(const string& input, Rng& rng, bool plus_one=false){
	// Special case when input is empty. Some mutations may want to insert at
	// index 0. In that case, `plus_one` must be true
	if (input.empty()){
		assert(plus_one);
		return 0;
	}
	return rng.rnd_exp(0, input.size() - (!plus_one));
}

void Corpus::mut_shrink(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Offset to remove data at
	size_t offset = rand_offset(input, rng);

	// Maximum number of bytes we'll remove.
	// 15/16 chance of removing at most 16 bytes
	//  1/16 chance of removing a random amount of bytes to the end of the input
	size_t max_remove = input.size() - offset;
	size_t rnd = rng.rnd(1, 16);
	max_remove = (rnd == 1 ? max_remove : min((size_t)16, max_remove));

	// Number of bytes we'll remove
	size_t to_remove = rng.rnd_exp(1, max_remove);

	// Remove bytes
	input.erase(offset, to_remove);
}

void Corpus::mut_expand(string& input, Rng& rng){
	// Check size
	if (input.size() >= m_max_input_size)
		return;

	// Offset to insert data at
	size_t offset = rand_offset(input, rng, true);

	// Maximum number of bytes we'll insert. Same as in `shrink`
	size_t max_expand = m_max_input_size - input.size();
	size_t rnd = rng.rnd(1, 16);
	max_expand = (rnd == 1 ? max_expand : min((size_t)16, max_expand));

	// Number of bytes we'll insert
	size_t to_expand = rng.rnd_exp(1, max_expand);

	// Insert bytes
	input.insert(offset, to_expand, '\x00');
}

void Corpus::mut_bit(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Flip random bit at random offset
	size_t offset  = rand_offset(input, rng);
	uint8_t bit    = rng.rnd(0, 7);
	input[offset] ^= (1 << bit);
}

void Corpus::mut_inc_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Increment byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset]++;
}

void Corpus::mut_dec_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Decrement byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset]--;
}

void Corpus::mut_neg_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Negate byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset] = ~input[offset];
}

void Corpus::mut_add_sub(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Offset of the integer we'll modify
	size_t offset = rand_offset(input, rng);

	// Remaining bytes
	size_t remain = input.size() - offset;

	// Get the size of the integer we'll modify. The sum is explained later.
	size_t int_size;
	if (remain >= 8 + 7)
		int_size = 1 << rng.rnd(0, 3); // size 1, 2, 4 or 8
	else if (remain >= 4 + 3)
		int_size = 1 << rng.rnd(0, 2); // size 1, 2 or 4
	else if (remain >= 2 + 1)
		int_size = 1 << rng.rnd(0, 1); // size 1 or 2
	else
		int_size = 1;                  // size 1

	// Align offset to int size. This prevents undefined behaviour when
	// accessing unaligned memory
	// offset &= ~(int_size - 1);

	// Align pointer to prevent undefined behaviour when accessing unaligned
	// memory. This can increase raw_ptr up to int_size - 1 bytes. That's why
	// we have to at least max_int_size + (max_int_size - 1) bytes remaining.
	uintptr_t raw_ptr = (uintptr_t)input.c_str() + offset;
	size_t mask = int_size - 1;
	raw_ptr = (raw_ptr + mask) & ~mask;

	// Helper macros
	#define __builtin_bswap8(n) n
	#define bswap(sz, n) __builtin_bswap##sz(n)
	#define mut(sz, range) do { \
		/* Get the number we'll add, which can be negative */                  \
		int32_t delta = rng.rnd(1, (range)*2) - (range);                       \
		                                                                       \
		/* Read bytes, interpret them as an integer with random endianness, */ \
		/* add delta and store back those bytes */                             \
		uint##sz##_t* ptr = (uint##sz##_t*)raw_ptr;                            \
		uint##sz##_t n = *ptr;                                                 \
		bool swap_endianness = rng.rnd(0, 1) && (sz != 8);                     \
		if (swap_endianness)                                                   \
		    n = bswap(sz, n);                                                  \
		n += delta;                                                            \
		if (swap_endianness)                                                   \
		    n = bswap(sz, n);                                                  \
		*ptr = n;                                                              \
	} while (0)

	// Perform mutation specifying maximum number to add or substract depending
	// on int size
	if (int_size == 1){
		mut(8, 16);
	} else if (int_size == 2){
		mut(16, 4096);
	} else if (int_size == 4){
		mut(32, 1024 * 1024);
	} else {
		mut(64, 256 * 1024 * 1024);
	}

	#undef mut
}

void Corpus::mut_set(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Get offset, len and value to memset
	size_t  offset = rand_offset(input, rng);
	size_t  len    = rng.rnd_exp(1, input.size() - offset);
	uint8_t c      = rng.rnd(0, 255);

	// Replace
	input.replace(offset, len, len, c);
}

void Corpus::mut_swap(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Get random offsets and their remaining bytes
	size_t offset1 = rand_offset(input, rng);
	size_t offset2 = rand_offset(input, rng);
	size_t offset1_remaining = input.size() - offset1;
	size_t offset2_remaining = input.size() - offset2;

	// Get random length
	size_t len = rng.rnd_exp(1, min(offset1_remaining, offset2_remaining));

	// Save input[offset1 : offset1+len] into tmp
	string tmp = input.substr(offset1, len);

	// Set input[offset1 : offset1+len] = input[offset2 : offset2+len]
	input.replace(offset1, len, input, offset2, len);

	// Set input[offset2 : offset2+len] = tmp
	input.replace(offset2, len, tmp);
}

void Corpus::mut_copy(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Get random offsets and their remaining bytes
	size_t src = rand_offset(input, rng);
	size_t dst = rand_offset(input, rng);
	size_t src_remaining = input.size() - src;
	size_t dst_remaining = input.size() - dst;

	// Get random length
	size_t len = rng.rnd_exp(1, min(src_remaining, dst_remaining));

	// Replace
	input.replace(dst, len, input, src, len);
}

void Corpus::mut_inter_splice(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Check size
	if (input.size() >= m_max_input_size)
		return;

	// Get random offsets and a random length
	size_t src = rand_offset(input, rng);
	size_t dst = rand_offset(input, rng, true);
	size_t src_remaining = input.size() - src;
	size_t max_insert    = m_max_input_size - input.size();
	size_t len = rng.rnd_exp(1, min(src_remaining, max_insert));

	// Insert
	input.insert(dst, input, src, len);
}

inline void fill_rand_bytes(string& s, Rng& rng){
	size_t len = s.size();
	for (size_t i = 0; i < len; i++)
		s[i] = rng.rnd(0x00, 0xFF);
}

void Corpus::mut_insert_rand(string& input, Rng& rng){
	// Check size
	if (input.size() >= m_max_input_size)
		return;

	// Get one or two random bytes and insert them at a random offset
	size_t max_insert = m_max_input_size - input.size();
	size_t offset = rand_offset(input, rng, true);
	string bytes(min(rng.rnd(1,2), max_insert), '\x00');
	fill_rand_bytes(bytes, rng);
	input.insert(offset, bytes);
}

void Corpus::mut_overwrite_rand(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Overwrite one or two input bytes with random bytes
	size_t offset = rand_offset(input, rng);
	size_t len    = (input.size()-offset > 1 ? rng.rnd(1, 2) : 1);
	string bytes(len, '\x00');
	fill_rand_bytes(bytes, rng);
	input.replace(offset, len, bytes);
}

void Corpus::mut_byte_repeat_overwrite(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Get random offset and amount
	size_t offset = rand_offset(input, rng);
	size_t amount = rng.rnd_exp(1, input.size() - offset);

	// Get byte to repeat and overwrite `amount` bytes with it
	char val = input[offset];
	for (size_t i = 0; i < amount; i++)
		input[offset + i + 1] = val;
}

void Corpus::mut_byte_repeat_insert(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Check size
	if (input.size() >= m_max_input_size)
		return;

	// Get random offset and amount
	size_t offset = rand_offset(input, rng);
	size_t max_amount = m_max_input_size - input.size();
	size_t amount = rng.rnd_exp(1, min(input.size() - offset, max_amount));

	// Get byte to repeat and insert it `amount` times
	char val = input[offset];
	string bytes(amount, val);
	input.insert(offset, bytes);
}

void Corpus::mut_magic_overwrite(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Get random offset and magic value
	size_t offset = rand_offset(input, rng);
	string magic_value = MAGIC_VALUES[rng.rnd(0, MAGIC_VALUES.size()-1)];

	// Truncate magic value if needed
	size_t remain = input.size() - offset;
	size_t len    = min(magic_value.size(), remain);

	// Replace bytes with magic value
	input.replace(offset, len, magic_value, 0, len);
}

void Corpus::mut_magic_insert(string& input, Rng& rng){
	// Check size
	if (input.size() >= m_max_input_size)
		return;

	// Get random offset and magic value
	size_t offset = rand_offset(input, rng, true);
	string magic_value = MAGIC_VALUES[rng.rnd(0, MAGIC_VALUES.size()-1)];

	// Truncate magic value if needed
	size_t max_len = m_max_input_size - input.size();
	size_t len     = min(magic_value.size(), max_len);

	// Insert magic value
	input.insert(offset, magic_value, 0, len);
}

void Corpus::mut_random_overwrite(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Get random offset and amount to overwrite
	size_t offset = rand_offset(input, rng);
	size_t amount = rng.rnd_exp(1, input.size() - offset);

	// Get random bytes
	string bytes(amount, '\x00');
	fill_rand_bytes(bytes, rng);

	// Replace with random bytes
	input.replace(offset, amount, bytes);
}

void Corpus::mut_random_insert(string& input, Rng& rng){
	// Check size
	if (input.size() >= m_max_input_size)
		return;

	// Get random offset and amount to insert
	size_t offset = rand_offset(input, rng, true);
	size_t max_amount = m_max_input_size - input.size();
	size_t amount = rng.rnd_exp(0, min(input.size() - offset, max_amount));

	// Get random bytes
	string bytes(amount, '\x00');
	fill_rand_bytes(bytes, rng);

	// Insert random bytes
	input.insert(offset, bytes);
}

void Corpus::mut_splice_overwrite(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Get the random input we'll copy from and check it is not empty
	// TODO: need lock here?
	const string& inp = m_corpus[rng.rnd(0, m_corpus.size()-1)];
	if (inp.empty())
		return;

	// Get dst and src offsets and lengths, making sure we don't exceed
	// max_input_size when replacing
	size_t dst_off = rand_offset(input, rng);
	size_t dst_len = rng.rnd_exp(1, input.size() - dst_off);
	size_t src_off = rand_offset(inp, rng);
	size_t max_src_len = m_max_input_size - input.size() + dst_len;
	size_t src_len = rng.rnd_exp(1, min(inp.size() - src_off, max_src_len));

	// Replace
	input.replace(dst_off, dst_len, inp, src_off, src_len);
}

void Corpus::mut_splice_insert(string& input, Rng& rng){
	// Check size
	if (input.size() >= m_max_input_size)
		return;

	// Get the random input we'll copy from and check it is not empty
	// TODO: need lock here?
	const string& inp = m_corpus[rng.rnd(0, m_corpus.size()-1)];
	if (inp.empty())
		return;

	// Get dst and src offsets and src length, making sure we don't exceed
	// max_input_size when inserting
	size_t dst_off = rand_offset(input, rng, true);
	size_t src_off = rand_offset(inp, rng);
	size_t max_src_len = m_max_input_size - input.size();
	size_t src_len = rng.rnd_exp(1, min(inp.size() - src_off, max_src_len));

	// Insert
	input.insert(dst_off, inp, src_off, src_len);
}
