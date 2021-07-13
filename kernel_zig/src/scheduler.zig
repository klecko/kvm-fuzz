usingnamespace @import("common.zig");
const Process = @import("process/Process.zig");
const mem = @import("mem/mem.zig");
const Allocator = std.mem.Allocator;

var active_idx: usize = 0;
var processes: std.ArrayList(*Process) = undefined;

pub fn init(allocator: *Allocator, first_process: *Process) void {
    processes = std.ArrayList(*Process).init(allocator);
    processes.append(first_process) catch unreachable;
}

pub fn current() *Process {
    return processes.items[active_idx];
}
