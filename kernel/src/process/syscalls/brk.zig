usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const log = std.log.scoped(.sys_brk);

// sys_brk never returns an error. In case of an error, it just returns the
// current brk.

fn sys_brk(self: *Process, addr: usize) usize {
    log.debug("brk: trying to set to 0x{x}, current is 0x{x}\n", .{ addr, self.brk });
    if (addr < self.min_brk)
        return self.brk;

    const brk_next_page = mem.alignPageForward(self.brk);
    const brk_cur_page = mem.alignPageBackward(self.brk);
    const addr_next_page = mem.alignPageForwardChecked(addr) catch return self.brk;
    if (addr > brk_next_page) {
        // We have to allocate space
        const size = addr_next_page - brk_next_page;
        self.space.mapRange(brk_next_page, size, .{ .read = true, .write = true }, .{}) catch |err| switch (err) {
            error.OutOfMemory, error.NotUserRange => return self.brk,
            error.AlreadyMapped => unreachable,
        };
    } else if (addr <= brk_cur_page) {
        // We have to free space
        const size = brk_next_page - addr_next_page;
        self.space.unmapRange(addr_next_page, size) catch |err| switch (err) {
            error.NotMapped, error.NotUserRange => unreachable,
            // OOM should be impossible here, as we are not splitting any region.
            error.OutOfMemory => unreachable,
        };
    }

    log.debug("brk: set to 0x{x}\n", .{addr});
    self.brk = addr;
    return self.brk;
}

pub fn handle_sys_brk(self: *Process, arg0: usize) usize {
    const addr = arg0;
    return sys_brk(self, arg0);
}
