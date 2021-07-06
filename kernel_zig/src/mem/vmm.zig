usingnamespace @import("../common.zig");
const x86 = @import("../x86/x86.zig");
const log = std.log.scoped(.vmm);

pub var kernel_page_table: x86.paging.KernelPageTable = undefined;

pub fn init() void {
    kernel_page_table = x86.paging.KernelPageTable.init();
    log.debug("VMM initialized\n", .{});
}
