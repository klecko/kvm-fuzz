#ifndef _COVERAGE_INTEL_PT_H
#define _COVERAGE_INTEL_PT_H

#include <vector>
#include <atomic>
#include <immintrin.h>
#include "common.h"

class CoverageIntelPT {
public:
	CoverageIntelPT();
	bool operator==(const CoverageIntelPT& other) const;

	uint8_t* bitmap();
	const uint8_t* bitmap() const;

	void reset();

private:
	std::vector<uint8_t> m_bitmap;
};

class SharedCoverageIntelPT : CoverageIntelPT {
public:
	using CoverageIntelPT::operator=;

	SharedCoverageIntelPT();

	// Number of edges added with `add`
	size_t count() const;

	bool add(const CoverageIntelPT& other);

private:
	std::atomic<size_t> m_bitmap_count;
};


inline CoverageIntelPT::CoverageIntelPT()
	: m_bitmap(COVERAGE_BITMAP_SIZE)
{
}

inline bool CoverageIntelPT::operator==(const CoverageIntelPT& other) const {
	return m_bitmap == other.m_bitmap;
}

inline uint8_t* CoverageIntelPT::bitmap() {
	return m_bitmap.data();
}

inline const uint8_t* CoverageIntelPT::bitmap() const {
	return m_bitmap.data();
}

inline void CoverageIntelPT::reset() {
	memset(m_bitmap.data(), 0, m_bitmap.size());
}


inline SharedCoverageIntelPT::SharedCoverageIntelPT()
	: CoverageIntelPT()
	, m_bitmap_count(0)
{
}

inline size_t SharedCoverageIntelPT::count() const {
	return m_bitmap_count;
}

// Bit test and set: set a bit and return its previous value atomically
__attribute__((always_inline)) inline
bool lock_bts(int i, uint8_t* p) {
	bool test = false;
	asm(
		"lock bts %[i], %[val];"
		"setc %[test];"
		: [val] "+m" (*p),
		  [test] "+r" (test)
		: [i] "r" (i)
		: "cc"
	);
	return test;
}

// The type we'll use to iterate the bitmap
#if defined(__AVX2__)
typedef __m256i_u word_t;
#elif defined(__SSE2__)
typedef __m128i_u word_t;
#elif defined(__SIZEOF_INT128__)
typedef __uint128_t word_t;
#else
typedef size_t word_t;
#endif

static size_t add_bits_in_word_at_byte(size_t i, uint8_t* bitmap, const uint8_t* other_bitmap) {
	// Check each of the bytes of the word starting at byte i.
	size_t new_cov = 0;
	for (size_t j = i*8; j < (i + sizeof(word_t))*8; j++) {
		size_t j_q = j / 8;
		size_t j_r = j % 8;
		if (other_bitmap[j_q] & (1 << j_r)) {
			// Set bit in our bitmap. If it was 0, then that's a new bit
			new_cov += !lock_bts(j_r, &bitmap[j_q]);
		}
	}
	return new_cov;
}

inline bool SharedCoverageIntelPT::add(const CoverageIntelPT& other) {
	static_assert(COVERAGE_BITMAP_SIZE % sizeof(word_t) == 0);

	uint8_t *bitmap = this->bitmap();
	const uint8_t* other_bitmap = other.bitmap();
	size_t new_cov = 0;

	// Go over both bitmaps using word_t. When there is new coverage in one
	// of those words, go over its bits to see which is the new one.
	for (size_t i = 0; i < COVERAGE_BITMAP_SIZE; i += sizeof(word_t)) {
		word_t cov_v       = *(word_t*)(bitmap + i);
		word_t other_cov_v = *(word_t*)(other_bitmap + i);
#if defined(__AVX2__)
		word_t comp = (cov_v | other_cov_v) == cov_v;
		bool equals = _mm256_movemask_epi8(comp) == 0xffffffff;
#elif defined(__SSE2__)
		word_t comp = (cov_v | other_cov_v) == cov_v;
		bool equals = _mm_movemask_epi8(comp) == 0xffff;
#else
		bool equals = (cov_v | other_cov_v) == cov_v;
#endif
		if (!equals) {
			// There is new coverage. Test each bit in the word.
			new_cov += add_bits_in_word_at_byte(i, bitmap, other_bitmap);
		}
	}

	m_bitmap_count += new_cov;
	return new_cov > 0;
}

#endif