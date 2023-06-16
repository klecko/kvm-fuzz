#include "mutator.h"
#include "magic_values.h"

using namespace std;

Mutator::Mutator(const std::vector<std::string>& corpus)
	: m_corpus(corpus)
	, m_max_input_size(1024)
{}

size_t Mutator::max_input_size() const {
	return m_max_input_size;
}

void Mutator::set_max_input_size(size_t size) {
	m_max_input_size = size;
}

void Mutator::mutate_input(string& input, Rng& rng, bool minimize){
	static_assert(MIN_MUTATIONS <= MAX_MUTATIONS, "invalid range");
	static_assert(MAX_MUTATIONS != 0, "MAX_MUTATIONS must be positive. To "
	              "disable mutations undef ENABLE_MUTATIONS instead.");
#ifndef ENABLE_MUTATIONS
	return;
#endif

	size_t n_muts = rng.rnd(MIN_MUTATIONS, MAX_MUTATIONS);
	mutation_strat_t mut_strat;
	if (!minimize) {
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



const vector<Mutator::mutation_strat_t> Mutator::mut_strats = {
	&Mutator::mut_shrink,
	&Mutator::mut_expand,
	&Mutator::mut_bit,
	&Mutator::mut_dec_byte,
	&Mutator::mut_inc_byte,
	&Mutator::mut_neg_byte,
	&Mutator::mut_add_sub,
	&Mutator::mut_set,
	&Mutator::mut_swap,
	&Mutator::mut_copy,
	&Mutator::mut_inter_splice,
	&Mutator::mut_insert_rand,
	&Mutator::mut_overwrite_rand,
	&Mutator::mut_byte_repeat_overwrite,
	&Mutator::mut_byte_repeat_insert,
	&Mutator::mut_magic_overwrite,
	&Mutator::mut_magic_insert,
	&Mutator::mut_random_overwrite,
	&Mutator::mut_random_insert,
	&Mutator::mut_splice_overwrite,
	&Mutator::mut_splice_insert,
};

const vector<Mutator::mutation_strat_t> Mutator::mut_strats_reduce = {
	&Mutator::mut_shrink,
	&Mutator::mut_bit,
	&Mutator::mut_dec_byte,
	&Mutator::mut_inc_byte,
	&Mutator::mut_neg_byte,
	&Mutator::mut_add_sub,
	&Mutator::mut_set,
	&Mutator::mut_swap,
	&Mutator::mut_copy,
};

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

void Mutator::mut_shrink(string& input, Rng& rng){
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

void Mutator::mut_expand(string& input, Rng& rng){
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

void Mutator::mut_bit(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Flip random bit at random offset
	size_t offset  = rand_offset(input, rng);
	uint8_t bit    = rng.rnd(0, 7);
	input[offset] ^= (1 << bit);
}

void Mutator::mut_inc_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Increment byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset]++;
}

void Mutator::mut_dec_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Decrement byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset]--;
}

void Mutator::mut_neg_byte(string& input, Rng& rng){
	// Check empty input
	if (input.empty())
		return;

	// Negate byte at random offset
	size_t offset = rand_offset(input, rng);
	input[offset] = ~input[offset];
}

void Mutator::mut_add_sub(string& input, Rng& rng){
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

void Mutator::mut_set(string& input, Rng& rng){
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

void Mutator::mut_swap(string& input, Rng& rng){
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

void Mutator::mut_copy(string& input, Rng& rng){
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

void Mutator::mut_inter_splice(string& input, Rng& rng){
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

void Mutator::mut_insert_rand(string& input, Rng& rng){
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

void Mutator::mut_overwrite_rand(string& input, Rng& rng){
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

void Mutator::mut_byte_repeat_overwrite(string& input, Rng& rng){
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

void Mutator::mut_byte_repeat_insert(string& input, Rng& rng){
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

void Mutator::mut_magic_overwrite(string& input, Rng& rng){
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

void Mutator::mut_magic_insert(string& input, Rng& rng){
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

void Mutator::mut_random_overwrite(string& input, Rng& rng){
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

void Mutator::mut_random_insert(string& input, Rng& rng){
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

void Mutator::mut_splice_overwrite(string& input, Rng& rng){
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

void Mutator::mut_splice_insert(string& input, Rng& rng){
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
