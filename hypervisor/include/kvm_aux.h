#ifndef _KVM_AUX_H
#define _KVM_AUX_H

#include <linux/kvm.h>

// too recent to be in linux/kvm.h
#ifndef KVM_CAP_DIRTY_LOG_RING
#define KVM_CAP_DIRTY_LOG_RING 192
#define KVM_DIRTY_LOG_PAGE_OFFSET 64
#define KVM_DIRTY_GFN_F_DIRTY           (1 << 0)
#define KVM_DIRTY_GFN_F_RESET           (1 << 1)
#define KVM_DIRTY_GFN_F_MASK            0x3
#define KVM_RESET_DIRTY_RINGS		_IO(KVMIO, 0xc7)
struct kvm_dirty_gfn {
	__u32 flags;
	__u32 slot; /* as_id | slot_id */
	__u64 offset;
};
#endif

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)
#define PDE64_SHARED (1U << 9) // custom
#define PDE64_NX (1LU << 63)

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 9)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

#define XCR0_X87 (1U << 0)
#define XCR0_SSE (1U << 1)
#define XCR0_AVX (1U << 2)
#define XCR0_OPMASK (1U << 5)
#define XCR0_ZMM_HI256 (1U << 6)
#define XCR0_HI16_ZMM (1U << 6)
#define XCR0_AVX512 (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)

/* x86-64 specific MSRs */
#define MSR_EFER             0xc0000080 /* extended feature register */
#define MSR_STAR             0xc0000081 /* legacy mode SYSCALL target */
#define MSR_LSTAR            0xc0000082 /* long mode SYSCALL target */
#define MSR_CSTAR            0xc0000083 /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK     0xc0000084 /* EFLAGS mask for syscall */
#define MSR_FS_BASE          0xc0000100 /* 64bit FS base */
#define MSR_GS_BASE          0xc0000101 /* 64bit GS base */
#define MSR_KERNEL_GS_BASE   0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX          0xc0000103 /* Auxiliary TSC */
#define MSR_FIXED_CTR0       0x00000309
#define MSR_FIXED_CTR1       0x0000030A
#define MSR_FIXED_CTR2       0x0000030B
#define MSR_FIXED_CTR_CTRL   0x0000038D
#define MSR_PERF_GLOBAL_CTRL 0x0000038F

// Page table stuff
#define PTL4_SHIFT 39
#define PTL4_BITS   9
#define PTL4_SIZE  (1UL << PTL4_SHIFT)
#define PTL4_MASK  (~(PTL4_SIZE - 1))
#define PTRS_PER_PTL4 (1UL << PTL4_BITS)
#define PTL4_INDEX(addr) ((addr >> PTL4_SHIFT) & (PTRS_PER_PTL4 - 1))

#define PTL3_SHIFT 30
#define PTL3_BITS   9
#define PTL3_SIZE  (1UL << PTL3_SHIFT)
#define PTL3_MASK  (~(PTL3_SIZE - 1))
#define PTRS_PER_PTL3 (1UL << PTL3_BITS)
#define PTL3_INDEX(addr) ((addr >> PTL3_SHIFT) & (PTRS_PER_PTL3 - 1))

#define PTL2_SHIFT 21
#define PTL2_BITS   9
#define PTL2_SIZE  (1UL << PTL2_SHIFT)
#define PTL2_MASK  (~(PTL2_SIZE - 1))
#define PTRS_PER_PTL2 (1UL << PTL2_BITS)
#define PTL2_INDEX(addr) ((addr >> PTL2_SHIFT) & (PTRS_PER_PTL2 - 1))

#define PTL1_SHIFT 12
#define PTL1_BITS  9
#define PTL1_SIZE  (1UL << PTL1_SHIFT)
#define PTL1_MASK  (~(PTL1_SIZE - 1))
#define PTRS_PER_PTL1 (1UL << PTL1_BITS)
#define PTL1_INDEX(addr) ((addr >> PTL1_SHIFT) & (PTRS_PER_PTL1 - 1))

#define PAGE_SIZE PTL1_SIZE
#define PAGE_OFFSET(addr) ((addr) & (~PTL1_MASK))
#define PAGE_CEIL(addr) (((addr) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define PHYS_MASK (0x000FFFFFFFFFF000)
#define PHYS_FLAGS(addr) ((addr) & (~PHYS_MASK))

// KVM VMX PT ioctls and stuff
#define KVM_VMX_PT_SETUP_FD                 _IO(KVMIO,  0xd0)        /* apply vmx_pt fd (via vcpu fd ioctl)*/
#define KVM_VMX_PT_CONFIGURE_ADDR0          _IOW(KVMIO, 0xd1, __u64) /* configure IP-filtering for addr0_a & addr0_b */
#define KVM_VMX_PT_CONFIGURE_ADDR1          _IOW(KVMIO, 0xd2, __u64) /* configure IP-filtering for addr1_a & addr1_b */
#define KVM_VMX_PT_CONFIGURE_ADDR2          _IOW(KVMIO, 0xd3, __u64) /* configure IP-filtering for addr2_a & addr2_b */
#define KVM_VMX_PT_CONFIGURE_ADDR3          _IOW(KVMIO, 0xd4, __u64) /* configure IP-filtering for addr3_a & addr3_b */

#define KVM_VMX_PT_CONFIGURE_CR3            _IOW(KVMIO, 0xd5, __u64) /* setup CR3 filtering value */
#define KVM_VMX_PT_ENABLE                   _IO(KVMIO,  0xd6)        /* enable and lock configuration */
#define KVM_VMX_PT_GET_TOPA_SIZE            _IOR(KVMIO, 0xd7, __u32) /* get defined ToPA size */
#define KVM_VMX_PT_DISABLE                  _IO(KVMIO,  0xd8)        /* enable and lock configuration */
#define KVM_VMX_PT_CHECK_TOPA_OVERFLOW      _IO(KVMIO,  0xd9)        /* check for ToPA overflow */

#define KVM_VMX_PT_ENABLE_ADDR0             _IO(KVMIO,  0xaa)        /* enable IP-filtering for addr0 */
#define KVM_VMX_PT_ENABLE_ADDR1             _IO(KVMIO,  0xab)        /* enable IP-filtering for addr1 */
#define KVM_VMX_PT_ENABLE_ADDR2             _IO(KVMIO,  0xac)        /* enable IP-filtering for addr2 */
#define KVM_VMX_PT_ENABLE_ADDR3             _IO(KVMIO,  0xad)        /* enable IP-filtering for addr3 */

#define KVM_VMX_PT_DISABLE_ADDR0            _IO(KVMIO,  0xae)        /* disable IP-filtering for addr0 */
#define KVM_VMX_PT_DISABLE_ADDR1            _IO(KVMIO,  0xaf)        /* disable IP-filtering for addr1 */
#define KVM_VMX_PT_DISABLE_ADDR2            _IO(KVMIO,  0xe0)        /* disable IP-filtering for addr2 */
#define KVM_VMX_PT_DISABLE_ADDR3            _IO(KVMIO,  0xe1)        /* disable IP-filtering for addr3 */

#define KVM_VMX_PT_ENABLE_CR3               _IO(KVMIO,  0xe2)        /* enable CR3 filtering */
#define KVM_VMX_PT_DISABLE_CR3              _IO(KVMIO,  0xe3)        /* disable CR3 filtering */

#define KVM_VMX_PT_SUPPORTED                _IO(KVMIO,  0xe4)

#define KVM_VMX_PT_CONFIGURE_HYPERCALL_HOOK _IOW(KVMIO, 0xe5, __u64) /* set address for hypercall hooks */

#define KVM_VMX_PT_RESET                    _IO(KVMIO, 0xf2)

#define KVM_EXIT_VMX_PT_TOPA_MAIN_FULL      119

struct vmx_pt_filter_iprs {
	__u64 a;
	__u64 b;
};

std::ostream& operator<<(std::ostream& os, const kvm_regs& regs);

#endif