usingnamespace @import("../common.zig");
const x86 = @import("x86.zig");
const mem = @import("../mem/mem.zig");
const log = std.log.scoped(.apic);

pub const TIMER_MICROSECS = 1000;

const APIC_DISABLE: u32 = 0x10000;
const APIC_SW_ENABLE: u32 = 0x100;
const APIC_CPUFOCUS: u32 = 0x200;
const APIC_NMI: u32 = 4 << 8;
const TMR_PERIODIC: u32 = 0x20000;
const TMR_BASEDIV: u32 = 1 << 20;

const APIC = struct {
    apic_vaddr: usize,

    const Register = enum(usize) {
        APIC_ID = 0x20,
        TASK_PRIORITY = 0x80,
        END_OF_INTERRUPT = 0xB0,
        LOGICAL_DESTINATION = 0xD0,
        DESTINATION_FORMAT = 0xE0,
        SPURIOUS_INTERRUPT_VECTOR = 0xF0,
        LVT_TIMER = 0x320,
        LVT_PERFORMANCE_MONITORING = 0x340,
        LVT_LINT0 = 0x350,
        LVT_LINT1 = 0x360,
        TIMER_INITIAL_COUNT = 0x380,
        TIMER_CURRENT_COUNT = 0x390,
        TIMER_DIVIDE_CONFIGURATION = 0x3e0,
    };

    fn getRegPtr(self: *APIC, reg: Register) *volatile u32 {
        return @intToPtr(*volatile u32, self.apic_vaddr + @enumToInt(reg));
    }

    fn writeReg(self: *APIC, reg: Register, value: u32) void {
        self.getRegPtr(reg).* = value;
    }

    fn readReg(self: *APIC, reg: Register) u32 {
        return self.getRegPtr(reg).*;
    }
};

/// The APIC itself.
var apic: APIC = undefined;

/// The value we'll set the APIC counter to in order to wait TIMER_MICROSECS.
/// This is calculated in init() using the PIT.
var counter_value: u32 = undefined;

// const Register = enum {
// 	ApicId = 0x20,
// 	TaskPriority = 0x80,
// 	EndOfInterrupt = 0xB0,
// 	LogicalDestination = 0xD0,
// 	DestinationFormat = 0xE0,
// 	SpuriousInterruptVector = 0xF0,
// 	LvtTimer = 0x320,
// 	LvtPerformanceMonitoring = 0x340,
// 	LvtLINT0 = 0x350,
// 	LvtLINT1 = 0x360,
// 	TimerInitialCount = 0x380,
// 	TimerCurrentCount = 0x390,
// 	TimerDivideConfiguration = 0x3e0,
// };

const Enable = struct {
    const XAPIC: u32 = 1 << 11;
    const X2APIC: u32 = 1 << 10;
};

const TimerMode = struct {
    const OneShot: u32 = 0;
    const Periodic: u32 = 0x20000;
};

const TimerDivide = struct {
    const Div1: u32 = 0xB;
    const Div2: u32 = 0x0;
    const Div4: u32 = 0x1;
    const Div8: u32 = 0x2;
    const Div16: u32 = 0x3;
    const Div32: u32 = 0x8;
    const Div64: u32 = 0x9;
    const Div128: u32 = 0xA;
};

pub fn init() void {
    // https://wiki.osdev.org/APIC_timer
    // Get APIC phys address
    var apic_phys_addr: usize = x86.rdmsr(.APIC_BASE);
    const apic_frame = apic_phys_addr & x86.paging.PHYS_MASK;

    // Map it at the end of the phymap
    apic.apic_vaddr = mem.pmm.physToVirt(usize, mem.pmm.memoryLength());
    mem.vmm.kernel_page_table.mapPage(apic.apic_vaddr, apic_frame, .{ .writable = true }) catch unreachable;

    // Initialize APIC
    apic.writeReg(.DESTINATION_FORMAT, 0x0FFFFFFFF);
    apic.writeReg(.LOGICAL_DESTINATION, (apic.readReg(.LOGICAL_DESTINATION) & 0x00FFFFFF) | 1);
    apic.writeReg(.LVT_TIMER, APIC_DISABLE);
    apic.writeReg(.LVT_PERFORMANCE_MONITORING, APIC_NMI);
    apic.writeReg(.LVT_LINT0, APIC_DISABLE);
    apic.writeReg(.LVT_LINT1, APIC_DISABLE);
    apic.writeReg(.TASK_PRIORITY, 0);

    // Enable APIC
    x86.wrmsr(.APIC_BASE, x86.rdmsr(.APIC_BASE) | Enable.XAPIC);
    apic.writeReg(.SPURIOUS_INTERRUPT_VECTOR, 0xFF | APIC_SW_ENABLE);

    // Enable timer in one-shot mode
    apic.writeReg(.LVT_TIMER, x86.idt.IRQNumber.APICTimer | TimerMode.OneShot);
    apic.writeReg(.TIMER_DIVIDE_CONFIGURATION, TimerDivide.Div16);

    // Calculate the counter value we'll set. We want the APIC to interrupt us
    // every TIMER_MICROSECS microsecs. Set counter to maximum value, sleep that
    // time using the PIT, stop counter, and calculate how much it has decreased
    // in that time.
    const initial_counter = std.math.maxInt(u32);
    apic.writeReg(.TIMER_INITIAL_COUNT, initial_counter);
    x86.pit.configureSleep(TIMER_MICROSECS);
    x86.pit.performSleep();
    apic.writeReg(.LVT_TIMER, APIC_DISABLE);
    const current_counter = apic.readReg(.TIMER_CURRENT_COUNT);
    counter_value = initial_counter - current_counter;

    // Set counter to the value we just calculated and re-enable timer,
    // this time in periodic mode.
    // x86.enableInterrupts();
    apic.writeReg(.TIMER_INITIAL_COUNT, counter_value);
    apic.writeReg(.LVT_TIMER, x86.idt.IRQNumber.APICTimer | TimerMode.Periodic);

    log.debug("APIC initialized\n", .{});
}

pub fn resetTimer() void {
    // Reset counter and signal end of interrupt
    apic.writeReg(.TIMER_INITIAL_COUNT, counter_value);
    apic.writeReg(.END_OF_INTERRUPT, 0);
}
