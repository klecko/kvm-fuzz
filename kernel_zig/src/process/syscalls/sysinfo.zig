usingnamespace @import("../common.zig");
const mem = @import("../../mem/mem.zig");
const UserPtr = mem.safe.UserPtr;

fn sys_sysinfo(self: *Process, info_ptr: UserPtr(*linux.sysinfo)) !void {
    const total_ram = mem.pmm.memoryLength();
    const free_ram = mem.pmm.amountFreeMemory();
    const used_ram = total_ram - free_ram;
    const total_swap = 2 * 1024 * 1024 * 1024;
    const info = linux.sysinfo{
        .uptime = 1234,
        .loads = .{ 30000, 20000, 15000 },
        .total_ram = total_ram,
        .free_ram = free_ram,
        .shared_ram = used_ram / 10,
        .buffer_ram = used_ram / 10,
        .total_swap = total_swap,
        .free_swap = total_swap,
        .procs = 1234,
        .total_high = 0,
        .free_high = 0,
        .mem_unit = 1,
    };
    try mem.safe.copyToUserSingle(linux.sysinfo, info_ptr, &info);
}

pub fn handle_sys_sysinfo(self: *Process, arg0: usize) !usize {
    const info_ptr = try UserPtr(*linux.sysinfo).fromFlat(arg0);
    try sys_sysinfo(self, info_ptr);
    return 0;
}
