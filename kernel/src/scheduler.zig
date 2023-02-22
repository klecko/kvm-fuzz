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
    if (!areChildAndParent(removing_process, process))
        return false;
    if (process.state != .waiting)
        return false;
    const pid_wait = process.state.waiting.pid;
    return if (pid_wait < -1)
        removing_process.pgid == -pid_wait
    else if (pid_wait == -1)
        true
    else if (pid_wait == 0)
        removing_process.pgid == process.pgid
    else
        removing_process.tgid == pid_wait;
}

fn removeProcess(idx: usize) void {
    // TODO: free it?
    log.debug("removing process {}\n", .{processes.items[idx].pid});
    processes.items[idx].destroy();
    _ = processes.orderedRemove(idx);
    std.debug.assert(idx != active_idx);
    if (active_idx > idx)
        active_idx -= 1;
}

fn writeExitCode(exit_code: i32, wstatus_ptr: ?mem.safe.UserPtr(*i32)) void {
    if (wstatus_ptr) |ptr| {
        const wstatus: i32 = exit_code << 8;
        mem.safe.copyToUserSingle(i32, ptr, &wstatus) catch {};
    }
}

pub fn exitCurrentProcessAndSchedule(exit_code: i32, frame: *Process.UserRegs) void {
    const removing_process = current();
    const removing_process_idx = active_idx;
    std.debug.assert(removing_process.state == .active);
    // print("exiting process {}\n", .{removing_process.pid});

    // Check if there's a process waiting for us. If that's the case, wake it up
    // and switch to it.
    for (processes.items) |process| {
        if (shouldWakeUp(process, removing_process)) {
            log.debug("waking up {}\n", .{process.pid});

            // Set rax for wait syscall return value
            process.user_regs.rax = @intCast(usize, removing_process.pid);

            // Switch
            const wstatus_ptr = process.state.waiting.wstatus_ptr;
            process.state = .active;
            switchToProcess(process, frame);

            // Now that we are in the waken up process context, write status
            writeExitCode(exit_code, wstatus_ptr);

            // Remove the process that exited, since it has already been waited for
            removeProcess(removing_process_idx);
            return;
        }
    }

    // Check if this is the last active process. In that case, check if there's
    // any stuck or zombie process and end the run.
    var active_processes: usize = 0;
    for (processes.items) |process| {
        if (process.state == .active) active_processes += 1;
    }
    if (active_processes == 1) {
        for (processes.items) |stuck_process| {
            switch (stuck_process.state) {
                .exited => {
                    // Emit warning if it's a thread from a different process
                    if (stuck_process.tgid != removing_process.tgid)
                        log.warn("zombie process {}, tgid {}\n", .{ stuck_process.pid, stuck_process.tgid });
                },
                .active => {}, // this is removing_process
                else => log.warn("stuck process {}, state {}\n", .{ stuck_process.pid, stuck_process.state }),
            }
        }
        hypercalls.endRun(.Exit, null);
    }

    // Keep the process with exited state, in case any other process waits for it
    removing_process.state = .{ .exited = exit_code };

    // Finally, schedule
    schedule(frame);
}

// Implements process waiting for a given pid, with semantics as in wait4 syscall.
// If the process we waited for has already exited, it returns its tgid and it
// doesn't schedule. Otherwise, it returns null, sets process state to waiting
// and schedules.
pub fn processWaitPid(
    process: *Process,
    pid: linux.pid_t,
    wstatus_ptr: ?mem.safe.UserPtr(*i32),
    regs: *Process.UserRegs,
) !?linux.pid_t {
    std.debug.assert(current() == process);

    // Update state
    process.state = State{ .waiting = .{ .pid = pid, .wstatus_ptr = wstatus_ptr } };
    errdefer process.state = .active;

    // Make sure there's some child that could wake us up when he finishes
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
            // No need to sleep
            process.state = .active;

            writeExitCode(exited_process.state.exited, wstatus_ptr);

            // Actually remove exited process, so we can't wait for it twice
            const ret = exited_process.tgid;
            removeProcess(i);
            return ret;
        }
    }

    // Schedule
    schedule(regs);
    if (current() == process)
        panic("deadlock\n", .{});
    return null;
}

pub fn wakeProcessesWaitingForFutex(
    uaddr: usize,
    mask: u32,
    num: u32,
) usize {
    if (num == 0)
        return 0;

    var woken_up: usize = 0;
    for (processes.items) |process| {
        if (process.state == .futex) {
            const futex = process.state.futex;
            if (futex.uaddr == uaddr and futex.mask & mask != 0) {
                // print("waking up from futex process {}\n", .{process.pid});
                process.state = .active;
                process.user_regs.rax = 0;
                woken_up += 1;
                if (woken_up == num)
                    break;
            }
        }
    }
    return woken_up;
}

fn getNextProcessIdx() usize {
    const prev_idx = active_idx;
    var i = (active_idx + 1) % processes.items.len;
    while (processes.items[i].state != .active) {
        i = (i + 1) % processes.items.len;
        if (i == prev_idx + 1)
            @panic("deadlock: no active process");
    }
    return i;
}

pub fn switchToProcess(next: *const Process, frame: anytype) void {
    const next_idx = std.mem.indexOfScalar(*const Process, processes.items, next) orelse unreachable;
    return switchToProcessIdx(next_idx, frame);
}

pub fn switchToProcessIdx(next_idx: usize, frame: anytype) void {
    std.debug.assert(next_idx != active_idx);
    std.debug.assert(processes.items[next_idx].state == .active);

    const cur = current();
    const next = processes.items[next_idx];
    active_idx = next_idx;
    log.info("switching from {} to {}\n", .{ cur.pid, next.pid });

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
    cur.user_regs.rflags = frame.rflags;

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
    frame.rflags = next.user_regs.rflags;

    // Switch address space if needed
    if (!std.meta.eql(cur.space, next.space)) {
        // if (cur.space.page_table.ptl4 != next.space.page_table.ptl4) {
        // log.info("switch address space\n", .{});
        next.space.load();
    }

    // Change fs base if needed
    std.debug.assert(x86.rdmsr(.FS_BASE) == cur.fs_base);
    if (cur.fs_base != next.fs_base) {
        x86.wrmsr(.FS_BASE, next.fs_base);
    }
}

pub fn schedule(frame: anytype) void {
    if (processes.items.len == 1)
        return;

    const next_idx = getNextProcessIdx();
    if (next_idx == active_idx)
        return;

    switchToProcessIdx(next_idx, frame);
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
