#ifndef _MEM_H
#define _MEM_H

#include "x86.h"

namespace Mem {
	namespace Phys {
		void init_memory();
		uintptr_t alloc_frame();
		void free_frame(uintptr_t frame);
		void* virt(uintptr_t phys);
		size_t amount_free_memory();
	}

	namespace Virt {
		void* alloc(size_t len, uint64_t flags);
		void  alloc(void* addr, size_t len, uint64_t flags);
		void* alloc_user_stack();
		bool is_range_free(void* addr, size_t len);
		void free(void* addr, size_t len);
		void set_flags(void* addr, size_t len, uint64_t flags);
		bool enough_free_memory(size_t length);
	}
}

#endif