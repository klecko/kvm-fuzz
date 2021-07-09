/// Lower half end
pub const user_end: usize = 0x800000000000;

/// Higher half start
pub var higher_half: usize = 0xFFFF800000000000;

/// Address of the last PTL4 entry in x86-64. Kernel should use memory from
/// this point on, so kernel memory is mapped in this PTL4 entry.
pub const kernel_start: usize = 0xFFFFFF8000000000;

/// Start of the virtual mapping of all the physical memory.
pub const physmap: usize = 0xFFFFFF8000000000;

/// Kernel initial brk (first page after kernel ELF in memory), and start of
/// kernel heap. This is set at start using `hypercalls.getKernelBrk`.
/// It was 0xFFFFFFFF8022E000 last time I checked.
pub var kernel_brk: usize = undefined;
