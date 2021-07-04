const gdt = @import("gdt.zig");
const idt = @import("idt.zig");

pub const MSR = enum {
    /// physical address of APIC
    APIC_BASE = 0x0000001B,

    /// extended feature register
    EFER = 0xc0000080,

    /// legacy mode SYSCALL target
    STAR = 0xc0000081,

    /// long mode SYSCALL target
    LSTAR = 0xc0000082,

    /// compat mode SYSCALL target
    CSTAR = 0xc0000083,

    /// EFLAGS mask for syscall
    SYSCALL_MASK = 0xc0000084,

    /// 64bit FS base
    FS_BASE = 0xc0000100,

    /// 64bit GS base
    GS_BASE = 0xc0000101,

    /// SwapGS GS shadow
    KERNEL_GS_BASE = 0xc0000102,

    /// Auxiliary TSC
    TSC_AUX = 0xc0000103,

    FIXED_CTR0 = 0x00000309,

    FIXED_CTR_CTRL = 0x0000038D,

    PERF_GLOBAL_CTRL = 0x0000038F,
};

pub fn wrmsr(msr: MSR, value: u64) void {
    asm volatile ("wrmsr"
        :
        : [msr] "{rcx}" (msr),
          [value_low] "{rax}" (value & 0xFFFFFFFF),
          [value_high] "{rdi}" (value >> 32)
        : "memory"
    );
}

pub fn lgdt(gdt_ptr: *const gdt.GDTPtr) void {
    asm volatile ("lgdt (%[gdt_ptr])"
        :
        : [gdt_ptr] "r" (gdt_ptr)
    );
}

pub fn ltr(tss_segment_selector: gdt.SegmentSelector) void {
    asm volatile ("ltr %[tss_segment_selector]"
        :
        : [tss_segment_selector] "r" (@enumToInt(tss_segment_selector))
    );
}

pub fn lidt(idt_ptr: *const idt.IDTPtr) void {
    asm volatile ("lidt (%[idt_ptr])"
        :
        : [idt_ptr] "r" (idt_ptr)
    );
}

pub fn rdcr2() u64 {
    return asm volatile ("mov %%cr2, %[ret]"
        : [ret] "=r" (-> u64)
    );
}
