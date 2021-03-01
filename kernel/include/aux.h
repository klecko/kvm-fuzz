/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)
#define PDE64_NX 0 // (1LU << 63) // TODO

/* x86-64 specific MSRs */
#define MSR_EFER		0xc0000080 /* extended feature register */
#define MSR_STAR		0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR		0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR		0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK	0xc0000084 /* EFLAGS mask for syscall */
#define MSR_FS_BASE		0xc0000100 /* 64bit FS base */
#define MSR_GS_BASE		0xc0000101 /* 64bit GS base */
#define MSR_KERNEL_GS_BASE	0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX		0xc0000103 /* Auxiliary TSC */