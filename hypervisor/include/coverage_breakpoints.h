#ifndef _COVERAGE_BREAKPOINTS_H
#define _COVERAGE_BREAKPOINTS_H

#include <set>
#include <unordered_set>
#include <atomic>
#include "common.h"

template <class SetContainer = std::set<vaddr_t>>
class CoverageBreakpoints {
public:
	bool operator==(const CoverageBreakpoints& other) const;

	// We want to be able to use this even when the other template type differs
	// from ours
	template <class T>
	CoverageBreakpoints<SetContainer>& operator=(const CoverageBreakpoints<T>& other);

	SetContainer& blocks();
	const SetContainer& blocks() const;

	void reset();

	bool contains(vaddr_t basic_block);

	bool add(vaddr_t basic_block);

	void remove(vaddr_t basic_block);

	// These are just used in the afl-cmin algorithm and may be removed later
	typename SetContainer::iterator begin();
	typename SetContainer::iterator end();

private:
	SetContainer m_basic_blocks;
};


class SharedCoverageBreakpoints : public CoverageBreakpoints<std::unordered_set<vaddr_t>> {
public:
	using CoverageBreakpoints::operator=;
	bool add(vaddr_t) = delete;

	// Number of basic blocks added with `add`
	size_t count() const;

	template <class T>
	bool add(const CoverageBreakpoints<T>& other);

private:
	std::atomic_flag m_lock = ATOMIC_FLAG_INIT;
};



template <class T>
bool CoverageBreakpoints<T>::operator==(const CoverageBreakpoints<T>& other) const {
	return m_basic_blocks == other.m_basic_blocks;
}

template <class T1>
template <class T2>
CoverageBreakpoints<T1>& CoverageBreakpoints<T1>::operator=(
	const CoverageBreakpoints<T2>& other
) {
	const T2& other_blocks = other.blocks();
	m_basic_blocks.clear();
	m_basic_blocks.insert(other_blocks.begin(), other_blocks.end());
	return *this;
}

template <class T>
inline T& CoverageBreakpoints<T>::blocks() {
	return m_basic_blocks;
}

template <class T>
inline const T& CoverageBreakpoints<T>::blocks() const {
	return m_basic_blocks;
}

template <class T>
inline void CoverageBreakpoints<T>::reset() {
	m_basic_blocks.clear();
}

template <class T>
inline bool CoverageBreakpoints<T>::contains(vaddr_t basic_block) {
	return m_basic_blocks.count(basic_block);
}

template <class T>
inline bool CoverageBreakpoints<T>::add(vaddr_t basic_block) {
	bool inserted = m_basic_blocks.insert(basic_block).second;
	return inserted;
}

template <class T>
inline void CoverageBreakpoints<T>::remove(vaddr_t basic_block) {
	m_basic_blocks.erase(basic_block);
}

template <class T>
typename T::iterator CoverageBreakpoints<T>::begin() {
	return m_basic_blocks.begin();
}

template <class T>
typename T::iterator CoverageBreakpoints<T>::end() {
	return m_basic_blocks.end();
}

inline size_t SharedCoverageBreakpoints::count() const {
	return blocks().size();
}

template <class T>
inline bool SharedCoverageBreakpoints::add(const CoverageBreakpoints<T>& other) {
	while (m_lock.test_and_set());

	// Insert every block of `other`, and check if any was added.
	// This could also be done as a bitmap if we want more performance, but
	// it isn't worth it for now.
	size_t prev_count = count();
	blocks().insert(other.blocks().begin(), other.blocks().end());
	bool new_cov = count() != prev_count;

	m_lock.clear();
	return new_cov;
}


#endif