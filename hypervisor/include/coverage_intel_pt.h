#ifndef _COVERAGE_INTEL_PT_H
#define _COVERAGE_INTEL_PT_H

#include <vector>
#include <atomic>
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
inline bool SharedCoverageIntelPT::add(const CoverageIntelPT& other) {
	static_assert(COVERAGE_BITMAP_SIZE % sizeof(size_t) == 0);
	size_t new_cov = 0;
	size_t cov_v, other_cov_v, i, j, j_q, j_r;

	uint8_t *bitmap = this->bitmap();
	const uint8_t* other_bitmap = other.bitmap();

	// Go over both bitmaps using size_t. When there is new coverage in one
	// of those words, go over its bits to see which is the new one.
	for (i = 0; i < COVERAGE_BITMAP_SIZE; i += sizeof(cov_v)) {
		cov_v       = *(size_t*)(bitmap + i);
		other_cov_v = *(size_t*)(other_bitmap + i);
		if ((cov_v | other_cov_v) != cov_v) {
			// There is new coverage. Test each bit in other_cov_v
			for (j = i*8; j < (i+sizeof(size_t))*8; j++) {
				j_q = j / 8;
				j_r = j % 8;
				if (other_bitmap[j_q] & (1 << j_r)) {
					// Set bit in our bitmap. If it was 0, then that's
					// a new bit
					new_cov += !lock_bts(j_r, &bitmap[j_q]);
				}
			}
		}
	}

	m_bitmap_count += new_cov;
	return new_cov > 0;
}




#endif