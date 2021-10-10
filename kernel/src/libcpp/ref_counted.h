#include "common.h"

template<typename T>
class RefCounted {
public:
	RefCounted() : m_ref_count(1) {}

	T& ref() {
		return *ref_ptr();
	};

	T* ref_ptr() {
		m_ref_count++;
		return static_cast<T*>(this);
	}

	void unref() {
		ASSERT(m_ref_count > 0, "unref with ref_count = %lu", m_ref_count);
		m_ref_count--;
		if (m_ref_count == 0)
			delete this;
	};

private:
	size_t m_ref_count;
};