pub const heap = @import("heap.zig");
pub const pmm = @import("pmm.zig");
pub const vmm = @import("vmm.zig");
pub const safe = @import("safe.zig");
pub const layout = @import("layout.zig");
const address_space = @import("address_space.zig");
pub const AddressSpace = address_space.AddressSpace;
pub const Perms = address_space.Perms;
