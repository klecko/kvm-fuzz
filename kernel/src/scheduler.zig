const std = @import("std");
const common = @import("common.zig");
const print = common.print;
const panic = common.panic;
const Process = @import("process/Process.zig");
const State = Process.State;
const x86 = @import("x86/x86.zig");
const mem = @import("mem/mem.zig");
const hypercalls = @import("hypercalls.zig");
const linux = @import("linux.zig");
const InterruptFrame = @import("interrupts.zig").InterruptFrame;
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.scheduler);

var active_idx: usize = 0;
var processes: std.ArrayList(*Process) = undefined;

pub fn init(allocator: Allocator, first_process: *Process) void {
    processes = std.ArrayList(*Process).init(allocator);
    processes.append(first_process) catch unreachable;
}

pub fn current() *Process {
    return processes.items[active_idx];
}

pub fn addProcess(process: *Process) !void {
    try processes.append(process);
}

fn areChildAndParent(child: *const Process, parent: *const Process) bool {
    return child.ptgid == parent.tgid;
}

// Returns whether `process` should be waken up when `removing_process` finishes
fn shouldWakeUp(process: *const Process, removing_process: *const Process) bool {
    // print("shouldWakeUp {}\n", .{process.state});
    return areChildAndParent(removing_process, process) and switch (process.state) {
        .waiting_for_any_with_pgid => |pgid| pgid == removing_process.pgid,
        .waiting_for_tgid => |tgid| tgid == removing_process.tgid,
        .waiting_for_any => true,
        else => false,
    };
}

fn removeProcess(idx: usize) void {
    // TODO: free it?
    print("removing process {}\n", .{processes.items[idx].pid});
    _ = processes.orderedRemove(idx);
    std.debug.assert(idx != active_idx);
    if (active_idx > idx)
        active_idx -= 1;
}

pub fn exitCurrentProcessAndSchedule(frame: *Process.UserRegs) void {
    const removing_process = current();
    const removing_process_idx = active_idx;
    print("exiting process {}\n", .{removing_process.pid});

    // First wake up other processes
    var was_waited_for = false;
    for (processes.items) |process| {
        if (shouldWakeUp(process, removing_process)) {
            was_waited_for = true;
            print("waking up {}\n", .{process.pid});
            process.state = .active;
            // Set rax for wait syscall return value
            process.user_regs.rax = @intCast(usize, removing_process.pid);
        }
    }

    // Check if this is the last active process
    if (!was_waited_for) {
        var active_processes: usize = 0;
        for (processes.items) |process| {
            if (process.state == .active) active_processes += 1;
        }
        if (active_processes == 1) {
            hypercalls.endRun(.Exit, null);
        }
    }

    // Now schedule and check deadlock
    schedule(frame);
    if (current() == removing_process)
        panic("deadlock\n", .{});

    // Remove process from list only if it was waited for. Otherwise keep it
    // with exited state, in case any other process waits for it.
    if (was_waited_for) {
        removeProcess(removing_process_idx);
    } else {
        removing_process.state = .exited;
    }

    // const idx = for (processes.items) |proc, i| {
    //     if (proc == process) break i;
    // } else panic("attempt to remove not found process\n", .{});
    // _ = processes.orderedRemove(idx);

}

// Implements process waiting for a given pid, with semantics as in wait4 syscall.
// If the process we waited for has already exited, it returns its tgid and it
// doesn't schedule. Otherwise, it returns null, sets process state to waiting
// and schedules.
pub fn processWaitPid(process: *Process, pid: linux.pid_t, regs: *Process.UserRegs) !?linux.pid_t {
    std.debug.assert(current() == process);

    // Update state
    process.state = if (pid < -1)
        State{ .waiting_for_any_with_pgid = -pid }
    else if (pid == -1)
        State{ .waiting_for_any = {} }
    else if (pid == 0)
        State{ .waiting_for_any_with_pgid = process.pgid }
    else
        State{ .waiting_for_tgid = pid };
    errdefer process.state = .active;

    // Make sure there's some wakeable child
    blk: {
        for (processes.items) |child| {
            if (shouldWakeUp(process, child)) break :blk;
        }
        return error.NoChild;
    }

    // Check if the process we are waiting for has already exited
    for (processes.items) |exited_process, i| {
        if (exited_process.state != .exited) continue;
        if (shouldWakeUp(process, exited_process)) {
            // Actually remove exited process, so we can't wait for it twice
            const ret = exited_process.tgid;
            removeProcess(i);

            // No need to sleep
            process.state = .active;
            return ret;
        }
    }

    // Schedule
    schedule(regs);
    if (current() == process)
        panic("deadlock\n", .{});
    return null;
}

fn nextProcess() void {
    active_idx = (active_idx + 1) % processes.items.len;
    while (processes.items[active_idx].state != .active) {
        active_idx = (active_idx + 1) % processes.items.len;
    }
}

pub fn schedule(frame: anytype) void {
    if (processes.items.len == 1)
        return;

    const cur = current();
    nextProcess();
    const next = current();

    if (next == cur)
        return;

    log.info("scheduling from {} to {}\n", .{ cur.pid, next.pid });

    // Save current process registers
    cur.user_regs.rax = frame.rax;
    cur.user_regs.rbx = frame.rbx;
    cur.user_regs.rcx = frame.rcx;
    cur.user_regs.rdx = frame.rdx;
    cur.user_regs.rbp = frame.rbp;
    cur.user_regs.rsi = frame.rsi;
    cur.user_regs.rdi = frame.rdi;
    cur.user_regs.r8 = frame.r8;
    cur.user_regs.r9 = frame.r9;
    cur.user_regs.r10 = frame.r10;
    cur.user_regs.r11 = frame.r11;
    cur.user_regs.r12 = frame.r12;
    cur.user_regs.r13 = frame.r13;
    cur.user_regs.r14 = frame.r14;
    cur.user_regs.r15 = frame.r15;
    cur.user_regs.rip = frame.rip;
    cur.user_regs.rsp = frame.rsp;

    // Set next process registers
    frame.rax = next.user_regs.rax;
    frame.rbx = next.user_regs.rbx;
    frame.rcx = next.user_regs.rcx;
    frame.rdx = next.user_regs.rdx;
    frame.rbp = next.user_regs.rbp;
    frame.rsi = next.user_regs.rsi;
    frame.rdi = next.user_regs.rdi;
    frame.r8 = next.user_regs.r8;
    frame.r9 = next.user_regs.r9;
    frame.r10 = next.user_regs.r10;
    frame.r11 = next.user_regs.r11;
    frame.r12 = next.user_regs.r12;
    frame.r13 = next.user_regs.r13;
    frame.r14 = next.user_regs.r14;
    frame.r15 = next.user_regs.r15;
    frame.rip = next.user_regs.rip;
    frame.rsp = next.user_regs.rsp;

    // Switch address space if needed
    if (!std.meta.eql(cur.space, next.space)) {
        // if (cur.space.page_table.ptl4 != next.space.page_table.ptl4) {
        // log.info("switch address space\n", .{});
        next.space.load();
    }

    // Change fs base if needed
    if (cur.fs_base != next.fs_base) {
        x86.wrmsr(.FS_BASE, next.fs_base);
    }

    // switchTasksAsm();
}

pub fn processWithPID(pid: linux.pid_t) ?*Process {
    for (processes.items) |process| {
        if (process.pid == pid)
            return process;
    }
    return null;
}

// fn switchTasksAsm() callconv(.Naked) void {
//     // aqui podemos llegar con la stack de la TSS (como resultado de una interrupcion),
//     // o con la stack de la syscall.
//     asm volatile (
//     // Push registers
//         \\push %%rax
//         \\push %%rbx
//         \\push %%rcx
//         \\push %%rdx
//         \\push %%rbp
//         \\push %%rsi
//         \\push %%rdi
//         \\push %%r8
//         \\push %%r9
//         \\push %%r10
//         \\push %%r11
//         \\push %%r12
//         \\push %%r13
//         \\push %%r14
//         \\push %%r15

//         // // Switch stacks
//         // \\mov %%rsp, [cur_rsp]
//         // \\mov [next_rsp], %%rsp

//         // // Set rsp0 in the TSS
//         // \\mov [next_rsp0], %%rax
//         // \\mov %%rax, [tss_rsp0]

//         // Switch stacks
//         \\mov %%rsp, (%[cur_rsp_ptr])
//         \\mov %[next_rsp], %%rsp

//         // Set rsp0 in the TSS
//         \\mov %[next_rsp0], %%rax
//         \\mov %%rax, (%[tss_rsp0_ptr])

//         // Restore registers
//         \\pop %%r15
//         \\pop %%r14
//         \\pop %%r13
//         \\pop %%r12
//         \\pop %%r11
//         \\pop %%r10
//         \\pop %%r9
//         \\pop %%r8
//         \\pop %%rdi
//         \\pop %%rsi
//         \\pop %%rbp
//         \\pop %%rdx
//         \\pop %%rcx
//         \\pop %%rbx
//         \\pop %%rax
//         \\ret

//         // : [next_rsp] "=m" (next.kernel_rsp),
//         //   [tss_rsp0] "=m" (x86.gdt.tss.rsp0)
//         :
//         : [cur_rsp_ptr] "r" (&cur.kernel_rsp),
//           [next_rsp0] "m" (next.kernel_rsp0),
//           [next_rsp] "m" (next.kernel_rsp),
//           [tss_rsp0_ptr] "r" (&x86.gdt.tss.rsp0),
//     );
// }
