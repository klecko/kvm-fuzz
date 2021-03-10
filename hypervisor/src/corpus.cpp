#include <iostream>
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <sys/stat.h>
#include "corpus.h"
#include "magic_values.h"

using namespace std;

string read_file(const string& filepath) {
	ifstream ifs(filepath);
	ASSERT(ifs.good(), "Error opening file %s", filepath.c_str());
	ostringstream ss;
	ss << ifs.rdbuf();
	ASSERT(ifs.good(), "Error reading file %s", filepath.c_str());
	return ss.str();
}

Corpus::Corpus(int nthreads, const string& folder)
	: m_lock_corpus(false)
	, m_lock_crashes(false)
	, m_mutated_inputs(nthreads)
	, m_recorded_cov_bitmap(new uint8_t[COVERAGE_BITMAP_SIZE])
	, m_recorded_cov(0)
{
	// Try to open the directory
	DIR* dir = opendir(folder.c_str());
	ERROR_ON(!dir, "opening directory %s", folder.c_str());

	// Iterate the directory
	struct dirent* ent;
	struct stat st;
	string filepath, input;
	size_t max_sz = 0;
	while ((ent = readdir(dir))){
		filepath = folder + "/" + ent->d_name;

		// Check file type. If readdir fails to provide it, fallback
		// to stat
		if (ent->d_type == DT_UNKNOWN){
			stat(filepath.c_str(), &st);
			if (!S_ISREG(st.st_mode))
				continue;
		} else if (ent->d_type != DT_REG)
			continue;

		// For each regular file, introduce its content into corpus
		input = read_file(filepath);
		m_corpus.push_back(input);

		// Record the size of the largest initial file
		max_sz = max(max_sz, input.size());

		//cout << "Read file '" << ent->d_name << "', size: "
		//     << input.size() << endl;
	}
	closedir(dir);

	// Set max_input_size to X times the size of the largest initial file
	// This will be the maximum size of inputs produced by mutations
	m_max_input_size = 10*max_sz;

	ASSERT(m_corpus.size() != 0, "empty corpus: %s", folder.c_str());
	cout << "Total files read: " << m_corpus.size() << endl;
	cout << "Max mutated input size: " << m_max_input_size << endl;

	// Reset coverage bitmap
	memset(m_recorded_cov_bitmap, 0, COVERAGE_BITMAP_SIZE);
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
	return m_recorded_cov;
}

const std::string& Corpus::get_new_input(int id, Rng& rng, Stats& stats){
	// Copy a random input to slot `id`, mutate it and return a
	// constant reference to it
	cycle_t cycles = rdtsc2();
	while (m_lock_corpus.test_and_set());
	m_mutated_inputs[id] = m_corpus[rng.rnd() % m_corpus.size()];
	m_lock_corpus.clear();
	stats.mut1_cycles += rdtsc2() - cycles;

	cycles = rdtsc2();
	mutate_input(id, rng);
	stats.mut2_cycles += rdtsc2() - cycles;
	return m_mutated_inputs[id];
}

void Corpus::report_crash(int id, const FaultInfo& fault) {
	// Try to insert fault information into our set
	while (m_lock_crashes.test_and_set());
	bool inserted = m_crashes.insert(fault).second;
	m_lock_crashes.clear();

	// If it was new, print fault information and dump input file to disk
	if (inserted) {
		cout << fault << endl;
		ostringstream filename;
		filename << fault.type_str() << "_0x" << hex << fault.rip << "_0x"
		         << fault.fault_addr;
		ofstream ofs("./crashes/" + filename.str());
		ofs << m_mutated_inputs[id];
		ERROR_ON(!ofs.good(), "Error saving crash file to disk");
		ofs.close();
	}
}

__attribute__((always_inline)) inline
bool lock_bts(int i, uint8_t* p) {
	bool test = false;
	asm(
		"lock bts %[i], %[val];"
		"setc %[test];"
		: [val] "+m" (*p),
		  [test] "+r" (test)
		: [i] "r" (i)
		:
	);
	return test;
}

void Corpus::report_coverage(int id, uint8_t* cov) {
	size_t new_cov = 0;
	size_t rec_cov_v, cov_v, i, j, j_q, j_r;

	// Go over both bitmaps using size_t. When there is new coverage in one
	// of those words, go over its bits to see which is the new one.
	for (i = 0; i < COVERAGE_BITMAP_SIZE; i += sizeof(cov_v)) {
		cov_v     = *(size_t*)(cov + i);
		rec_cov_v = *(size_t*)(m_recorded_cov_bitmap + i);
		if ((cov_v | rec_cov_v) != rec_cov_v) {
			// There is new coverage. Test each bit in cov_v
			for (j = i*8; j < (i+sizeof(size_t))*8; j++) {
				j_q = j / 8;
				j_r = j % 8;
				if (cov[j_q] & (1 << j_r)) {
					// Set bit in recorded cov bitmap. If it was 0, then that's
					// a new bit
					new_cov += !lock_bts(j_r, &m_recorded_cov_bitmap[j_q]);
				}
			}
		}
	}

	// If there was new coverage, update count and add input to corpus
	if (new_cov) {
		m_recorded_cov += new_cov;
		add_input(m_mutated_inputs[id]);
	}
}

void Corpus::add_input(const string& new_input){
	while (m_lock_corpus.test_and_set());
	m_corpus.push_back(new_input);
	m_lock_corpus.clear();
}

// MUTATION STUFF
// I don't remember a shit about this code and I'm not gonna bother reading it
const vector<Corpus::mutation_strat_t> Corpus::mut_strats = {
	&Corpus::shrink,
	&Corpus::expand,
	&Corpus::bit,
	&Corpus::dec_byte,
	&Corpus::inc_byte,
	&Corpus::neg_byte,
	&Corpus::add_sub,
	&Corpus::set,
	&Corpus::swap,
	&Corpus::copy,
	&Corpus::inter_splice,
	&Corpus::insert_rand,
	&Corpus::overwrite_rand,
	&Corpus::byte_repeat_overwrite,
	&Corpus::byte_repeat_insert,
	&Corpus::magic_overwrite,
	&Corpus::magic_insert,
	&Corpus::random_overwrite,
	&Corpus::random_insert,
	&Corpus::splice_overwrite,
	&Corpus::splice_insert,
};

void Corpus::mutate_input(int id, Rng& rng){
	string& input = m_mutated_inputs[id];
	mutation_strat_t mut_strat;
	for (size_t i = 0; i < rng.rnd(MIN_MUTATIONS, MAX_MUTATIONS); i++){
		mut_strat = mut_strats[rng.rnd(0, mut_strats.size()-1)];
		(this->*mut_strat)(input, rng);
	}
	ASSERT(input.size() <= m_max_input_size,
	       "input mutation too large: %ld/%ld", input.size(), m_max_input_size);
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

void Corpus::shrink(string& input, Rng& rng){
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

void Corpus::expand(string& input, Rng& rng){
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

void Corpus::bit(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Flip random bit at random offset
	size_t offset  = rand_offset(input, rng);
	uint8_t bit    = rng.rnd(0, 7);
	input[offset] ^= (1 << bit);
}

void Corpus::inc_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Increment byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset]++;
}

void Corpus::dec_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Decrement byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset]--;
}

void Corpus::neg_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Negate byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset] = ~input[offset];
}

void Corpus::add_sub(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Offset of the integer we'll modify
	size_t offset = rand_offset(input, rng);

	// Remaining bytes
	size_t remain = input.size() - offset;

	// Get the size of the integer we'll modify
	size_t int_size;
	if (remain >= 8)
		int_size = 1 << rng.rnd(0, 3); // size 1, 2, 4 or 8
	else if (remain >= 4)
		int_size = 1 << rng.rnd(0, 2); // size 1, 2 or 4
	else if (remain >= 2)
		int_size = 1 << rng.rnd(0, 1); // size 1 or 2
	else
		int_size = 1;                  // size 1

	// Helper macros
	#define __builtin_bswap8(n) n
	#define bswap(sz, n) __builtin_bswap##sz(n)
	#define mut(sz) do { \
		/* Get the number we'll add, which can be negative */                  \
		int32_t delta = rng.rnd(1, range*2) - range;                           \
		                                                                       \
		/* Read bytes, interpret them as an integer with random endianness, */ \
		/* add delta and store back those bytes */                             \
		uint##sz##_t n = *(uint##sz##_t*)(input.c_str()+offset);               \
		bool swap_endianness = rng.rnd(0, 1) && (sz != 8);                     \
		if (swap_endianness)                                                   \
		    n = bswap(sz, n);                                                  \
		n += delta;                                                            \
		if (swap_endianness)                                                   \
		    n = bswap(sz, n);                                                  \
		*(uint##sz##_t*)(input.c_str()+offset) = n;                            \
	} while (0)

	// Get maximum number to add or substract depending on int size and mutate
	size_t range;
	if (int_size == 1){
		range = 16;
		mut(8);
	} else if (int_size == 2){
		range = 4096;
		mut(16);
	} else if (int_size == 4){
		range = 1024 * 1024;
		mut(32);
	} else {
		range = 256 * 1024 * 1024;
		mut(64);
	}

	#undef mut
}

void Corpus::set(string& input, Rng& rng){
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

void Corpus::swap(string& input, Rng& rng){
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

void Corpus::copy(string& input, Rng& rng){
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

void Corpus::inter_splice(std::string& input, Rng& rng){
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

void Corpus::insert_rand(std::string& input, Rng& rng){
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

void Corpus::overwrite_rand(std::string& input, Rng& rng){
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

void Corpus::byte_repeat_overwrite(std::string& input, Rng& rng){
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

void Corpus::byte_repeat_insert(std::string& input, Rng& rng){
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

void Corpus::magic_overwrite(std::string& input, Rng& rng){
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

void Corpus::magic_insert(std::string& input, Rng& rng){
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

void Corpus::random_overwrite(std::string& input, Rng& rng){
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

void Corpus::random_insert(std::string& input, Rng& rng){
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

void Corpus::splice_overwrite(std::string& input, Rng& rng){
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

void Corpus::splice_insert(std::string& input, Rng& rng){
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
