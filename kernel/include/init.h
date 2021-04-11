#ifndef _INIT_H
#define _INIT_H

// Kernel startup functions, implemented in their respective files
namespace GDT {
	void init();
}

namespace IDT {
	void init();
}

namespace Syscall {
	void init();
}

#endif