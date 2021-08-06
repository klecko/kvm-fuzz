usingnamespace @import("common.zig");
const Process = @import("process/Process.zig");
const x86 = @import("x86/x86.zig");
const mem = @import("mem/mem.zig");
const hypercalls = @import("hypercalls.zig");
const Allocator = std.mem.Allocator;
const InterruptFrame = @import("interrupts.zig").InterruptFrame;
const log = std.log.scoped(.scheduler);

var active_idx: usize = 0;
var processes: std.ArrayList(*Process) = undefined;

pub fn init(allocator: *Allocator, first_process: *Process) void {
    processes = std.ArrayList(*Process).init(allocator);
    processes.append(first_process) catch unreachable;
}

pub fn current() *Process {
    return processes.items[active_idx];
}

pub fn addProcess(process: *Process) !void {
    try processes.append(process);
}

pub fn removeProcess(process: *Process) void {
    const idx = for (processes.items) |proc, i| {
        if (proc == process) break i;
    } else panic("attempt to remove not found process\n", .{});
    _ = processes.swapRemove(idx);

    if (processes.items.len == 0) {
        hypercalls.endRun(.Exit, null);
    }
}

pub fn schedule(frame: anytype) void {
    if (processes.items.len == 1)
        return;

    // log.info("scheduling\n", .{});
    const cur = current();
    active_idx = (active_idx + 1) % processes.items.len;
    const next = current();

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

    // switchTasksAsm();
}

fn switchTasksAsm() callconv(.Naked) void {
    // aqui podemos llegar con la stack de la TSS (como resultado de una interrupcion),
    // o con la stack de la syscall.
    asm volatile (
    // Push registers
        \\push %%rax
        \\push %%rbx
        \\push %%rcx
        \\push %%rdx
        \\push %%rbp
        \\push %%rsi
        \\push %%rdi
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        \\push %%r12
        \\push %%r13
        \\push %%r14
        \\push %%r15

        // // Switch stacks
        // \\mov %%rsp, [cur_rsp]
        // \\mov [next_rsp], %%rsp

        // // Set rsp0 in the TSS
        // \\mov [next_rsp0], %%rax
        // \\mov %%rax, [tss_rsp0]

        // Switch stacks
        \\mov %%rsp, (%[cur_rsp_ptr])
        \\mov %[next_rsp], %%rsp

        // Set rsp0 in the TSS
        \\mov %[next_rsp0], %%rax
        \\mov %%rax, (%[tss_rsp0_ptr])

        // Restore registers
        \\pop %%r15
        \\pop %%r14
        \\pop %%r13
        \\pop %%r12
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rdi
        \\pop %%rsi
        \\pop %%rbp
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rbx
        \\pop %%rax
        \\ret

        // : [next_rsp] "=m" (next.kernel_rsp),
        //   [tss_rsp0] "=m" (x86.gdt.tss.rsp0)
        :
        : [cur_rsp_ptr] "r" (&cur.kernel_rsp),
          [next_rsp0] "m" (next.kernel_rsp0),
          [next_rsp] "m" (next.kernel_rsp),
          [tss_rsp0_ptr] "r" (&x86.gdt.tss.rsp0)
    );
}
