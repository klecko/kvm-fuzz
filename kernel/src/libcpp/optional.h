#ifndef _OPTIONAL_H
#define _OPTIONAL_H

#include "common.h"

template<typename T>
class Optional {
public:
	Optional()
		: m_storage {0}
		, m_has_value(false)
	{}

	Optional(const T& value)
		: m_has_value(true)
	{
		new (m_storage) T(value);
	}

	Optional(T&& value)
		: m_has_value(true)
	{
		new (m_storage) T(move(value));
	}

	Optional(const Optional& other)
		: m_has_value(other.m_has_value)
	{
		if (m_has_value) {
			new (m_storage) T(other.value());
		}
	}

	Optional(Optional&& other)
		: m_has_value(other.m_has_value)
	{
		if (m_has_value) {
			new (m_storage) T(other.release_value());
			other.m_has_value = false;
		}
	}

	template<typename U>
	Optional(const U& value)
		: m_has_value(true)
	{
		new (&m_storage) T(value);
	}

	~Optional() {
		clear();
	}

	Optional& operator=(const Optional& other) {
		if (this != & other) {
			clear();
			m_has_value = other.m_has_value;
			if (m_has_value)
				new (m_storage) T(other.value());
		}
		return *this;
	}

	Optional& operator=(Optional&& other) {
		if (this != & other) {
			clear();
			m_has_value = other.m_has_value;
			if (m_has_value)
				new (m_storage) T(other.release_value());
		}
		return *this;
	}

	template<typename U>
	bool operator==(const Optional<U>& other) const {
		return has_value() == other.has_value() &&
		       (!has_value() || value() == other.value());
	}

	void clear() {
		if (m_has_value) {
			value().~T();
			m_has_value = false;
		}
	}

	bool has_value() const {
		return m_has_value;
	}

	const T& value() const {
		ASSERT(m_has_value, "no value");
		return *reinterpret_cast<const T*>(m_storage);
	}

	T release_value() {
		ASSERT(m_has_value, "no value");
		T released_value = move(value());
		value().~T();
		m_has_value = false;
		return released_value;
	}

	T value_or(const T& fallback) const {
		return (m_has_value ? value() : fallback);
	}

	const T& operator*() const {
		return value();
	}

	T& operator*() {
		return value();
	}

	const T* operator->() const {
		return &value();
	}

	T* operator->() {
		return &value();
	}

private:
	uint8_t m_storage[sizeof(T)];
	bool m_has_value;
};

#endif