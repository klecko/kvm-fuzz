/// Start address of the region where user mappings will be mapped.
pub const user_mappings_start: usize = 0x7FFFF7FFE000;

/// Start and size of the user stack (grows towards lower addresses)
pub const user_stack: usize = 0x800000000000;
pub const user_stack_size: usize = 0x10000;

/// End of the lower half.
pub const user_end: usize = 0x800000000000;

/// Start of the higher half.
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
