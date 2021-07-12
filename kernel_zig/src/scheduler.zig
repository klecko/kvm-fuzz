usingnamespace @import("common.zig");
const Process = @import("process.zig").Process;
const mem = @import("mem/mem.zig");

var active_idx: usize = 0;
var processes: std.ArrayList(*Process) = undefined;

pub fn init(first_process: *Process) void {
    processes = std.ArrayList(*Process).init(mem.heap.page_allocator);
    processes.append(first_process) catch unreachable;
}

pub fn current() *Process {
    return processes.items[active_idx];
}
