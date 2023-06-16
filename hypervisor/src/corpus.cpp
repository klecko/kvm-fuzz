#include <iostream>
#include <fstream>
#include <algorithm>
#include <limits>
#include <dirent.h>
#include <sys/stat.h>
#include "corpus.h"
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
	, m_mutator(m_corpus)
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
		input = utils::read_file(filepath);
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
	m_mutator.set_max_input_size(10*max_sz);

	// Set max_input_size to an absolute value
	// m_mutator.set_max_input_size(200*1024);

	ASSERT(m_corpus.size() != 0, "empty corpus: %s", m_input_dir.c_str());
	cout << "Total files read: " << m_corpus.size() << endl;
	cout << "Max mutated input size: " << m_mutator.max_input_size() << endl;

	// Create output directory (or do nothing if they existed).
	// Each mode we'll create the subdirectory they'll write their output to
	// here. Normal mode will write corpus and crashes dir, while each
	// minimization mode will write to its own directory.
	utils::create_folder(output_dir);
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
	return m_mutator.max_input_size();
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
	utils::write_file(m_output_dir_corpus + "/" + corpus_filename(i), m_corpus[i]);
}

void Corpus::write_crash_file(size_t i, const FaultInfo& fault) {
	ASSERT(m_mode == Mode::Normal, "mode %d", m_mode);
	utils::write_file(m_output_dir_crashes + "/" + fault.filename(), m_corpus[i]);
}

void Corpus::write_crash_file(int id, const FaultInfo& fault) {
	ASSERT(m_mode == Mode::Normal, "mode %d", m_mode);
	utils::write_file(m_output_dir_crashes + "/" + fault.filename(),
	                  m_mutated_inputs[id]);
}

void Corpus::write_min_corpus_file(size_t i) {
	ASSERT(m_mode == Mode::CorpusMinimization, "mode %d", m_mode);
	utils::write_file(m_output_dir_min_corpus+ "/" + min_corpus_filename(i),
	                  m_corpus[i]);
}

void Corpus::write_min_crash_file(size_t i) {
	ASSERT(m_mode == Mode::CrashesMinimization, "mode %d", m_mode);
	utils::write_file(m_output_dir_min_crashes + "/" + min_crash_filename(i),
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
	utils::create_folder(m_output_dir_corpus);
	utils::create_folder(m_output_dir_crashes);
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
	m_coverages_min = coverages;
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
	utils::create_folder(m_output_dir_min_corpus);
	for (size_t i = 0; i < m_corpus.size(); i++) {
		write_min_corpus_file(i);
	}
}

void Corpus::set_mode_crashes_min(const vector<FaultInfo>& faults) {
	ASSERT(m_mode == Mode::Unknown, "corpus mode already set to %d", m_mode);
	ASSERT(faults.size() == m_corpus.size(), "size mismatch: %lu vs %lu",
	       faults.size(), m_corpus.size());
	m_mode = Mode::CrashesMinimization;
	m_faults_min = faults;
	cout << "Set corpus mode: Crashes Minimization. Output directory will be "
	     << m_output_dir_min_crashes << endl;

	// Create output folder and write seed input files to disk
	utils::create_folder(m_output_dir_min_crashes);
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
		handle_crash_crashes_min(id, fault);
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

void Corpus::handle_crash_crashes_min(int id, const FaultInfo& fault) {
	// If the fault is the same as the one we're trying to minimize and
	// the size of the mutated input is lower than current input size,
	// replace current input with mutated input and save file to disk.
	size_t i = m_mutated_inputs_indexes[id];
	if (fault == m_faults_min[i]) {
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
			handle_cov_corpus_min(id, cov);
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

void Corpus::handle_cov_corpus_min(int id, const Coverage& cov) {
	// If the coverage is the same and the size of the mutated input is
	// lower than current input size, replace current input with mutated
	// input and save file to disk.
	size_t i = m_mutated_inputs_indexes[id];
	if (cov == m_coverages_min[i]) {
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
	ASSERT(m_coverages_min.size() == m_corpus.size(), "size mismatch: %lu vs %lu",
	       m_coverages_min.size(), m_corpus.size());

	// Calculate union of all coverages
	SharedCoverage missing_coverage;
	for (const Coverage& coverage : m_coverages_min) {
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
		for (size_t i = 0; i < m_coverages_min.size(); i++) {
			if (!m_coverages_min[i].contains(missing))
				continue;
			bool is_better = m_corpus[i].size() < m_corpus[i_winning].size();
			if (is_better || i_winning == INVALID_INDEX)
				i_winning = i;
		}
		ASSERT(i_winning != INVALID_INDEX, "there's no input that covers bb?");
		new_corpus.push_back(m_corpus[i_winning]);

		// 3. Register all basic blocks reached by the winning entry
		for (vaddr_t bb_reached : m_coverages_min[i_winning]) {
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

void Corpus::mutate_input(int id, Rng& rng){
	string& input = m_mutated_inputs[id];
	m_mutator.mutate_input(input, rng, m_mode != Mode::Normal);
}
