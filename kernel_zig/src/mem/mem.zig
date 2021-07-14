pub const heap = @import("heap.zig");
pub const pmm = @import("pmm.zig");
pub const vmm = @import("vmm.zig");
pub const safe = @import("safe.zig");
pub const layout = @import("layout.zig");
const address_space = @import("address_space.zig");
pub const AddressSpace = address_space.AddressSpace;
pub const Perms = address_space.Perms;

const std = @import("std");
pub fn isPageAligned(addr: usize) bool {
    return std.mem.isAligned(addr, std.mem.page_size);
}

pub fn alignPageForward(addr: usize) usize {
    return std.mem.alignForward(addr, std.mem.page_size);
}

pub fn alignPageForwardChecked(addr: usize) error{Overflow}!usize {
    const tmp: usize = std.mem.page_size - 1;
    return (try std.math.add(usize, addr, tmp)) & ~tmp;
}

pub fn alignPageBackward(addr: usize) usize {
    return std.mem.alignBackward(addr, std.mem.page_size);
}
