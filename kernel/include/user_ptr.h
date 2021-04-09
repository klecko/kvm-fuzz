#ifndef _USER_PTR_H
#define _USER_PTR_H

#include <stddef.h>

template<typename T> class UserPtr;

template<typename T>
class UserPtr<T*> {
public:
	explicit UserPtr(T* val)
		: m_ptr(val)
	{}

	explicit UserPtr(uintptr_t val)
		: m_ptr((T*)val)
	{}

	T* ptr() const {
		return m_ptr;
	}

	uintptr_t flat() const {
		return (uintptr_t)m_ptr;
	}

	UserPtr<T*> operator+(size_t n) const {
		return UserPtr<T*>(m_ptr + n);
	}

	void operator+=(size_t n) {
		m_ptr += n;
	}

	operator bool() const {
		return m_ptr;
	}

	operator UserPtr<void*>() const {
		return UserPtr<void*>(m_ptr);
	}

	operator UserPtr<const void*>() const {
		return UserPtr<const void*>(m_ptr);
	}

private:
	T* m_ptr;
};

#endif