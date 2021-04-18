#ifndef _MEM_HEAP_H
#define _MEM_HEAP_H

#include "common.h"

class Heap {
public:
	Heap();
	Heap(void* base);

	void init(void* base);

	void* alloc(size_t);
	void free(void*);
	size_t free_bytes();

private:
	static const size_t INITIAL_PAGES = 2;
	bool more(size_t n_pages);

	uint8_t* m_base;
	size_t m_used;
	size_t m_size;
};

#endif