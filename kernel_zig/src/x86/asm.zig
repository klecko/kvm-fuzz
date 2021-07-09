const x86 = @import("x86.zig");

pub const MSR = enum(usize) {
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
    asm volatile (
        \\wrmsr
        :
        : [msr] "{rcx}" (msr),
          [value_low] "{rax}" (value & 0xFFFFFFFF),
          [value_high] "{rdx}" (value >> 32)
        : "memory"
    );
}

pub fn rdmsr(msr: MSR) usize {
    var high: u32 = undefined;
    var low: u32 = undefined;
    asm volatile (
        \\rdmsr
        : [high] "={edx}" (high),
          [low] "={eax}" (low)
        : [msr] "{rcx}" (msr)
        : "memory"
    );
    return (@intCast(u64, high) << 32) | low;
}

pub fn lgdt(gdt_ptr: *const x86.gdt.GDTPtr) void {
    asm volatile (
        \\lgdt (%[gdt_ptr])
        :
        : [gdt_ptr] "r" (gdt_ptr)
    );
}

pub fn ltr(tss_segment_selector: x86.gdt.SegmentSelector) void {
    asm volatile (
        \\ltr %[tss_segment_selector]
        :
        : [tss_segment_selector] "r" (@enumToInt(tss_segment_selector))
    );
}

pub fn lidt(idt_ptr: *const x86.idt.IDTPtr) void {
    asm volatile (
        \\lidt (%[idt_ptr])
        :
        : [idt_ptr] "r" (idt_ptr)
    );
}

pub fn rdcr2() u64 {
    return asm volatile (
        \\mov %%cr2, %[ret]
        : [ret] "=r" (-> u64)
    );
}

pub fn rdcr3() u64 {
    return asm volatile (
        \\mov %%cr3, %[ret]
        : [ret] "=r" (-> u64)
    );
}

pub fn flush_tlb() void {
    asm volatile (
        \\mov %%cr3, %%rax
        \\mov %%rax, %%cr3
        ::: "memory", "rax");
}

pub fn flush_tlb_entry(page_vaddr: usize) void {
    asm volatile (
        \\invlpg (%[page])
        :
        : [page] "r" (page_vaddr)
        : "memory"
    );
}

pub fn outb(comptime port: u16, value: u8) void {
    asm volatile (
        \\outb %[value], %[port]
        :
        : [port] "im" (port),
          [value] "{al}" (value)
    );
}

pub fn inb(comptime port: u16) u8 {
    return asm volatile (
        \\inb %[port], %[value]
        : [value] "={al}" (-> u8)
        : [port] "im" (port)
    );
}

pub fn enableInterrupts() void {
    asm volatile ("sti");
}
