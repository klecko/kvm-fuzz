const std = @import("std");
const assert = std.debug.assert;
const mem = @import("../mem/mem.zig");
const common = @import("../common.zig");
const x86 = @import("x86.zig");
const log = std.log.scoped(.paging);

pub const PTL4_SHIFT = 39;
pub const PTL4_BITS = 9;
pub const PTL4_ENTRIES = 1 << PTL4_BITS;
pub fn PTL4_INDEX(addr: usize) usize {
    return (addr >> PTL4_SHIFT) & (PTL4_ENTRIES - 1);
}

pub const PTL3_SHIFT = 30;
pub const PTL3_BITS = 9;
pub const PTL3_ENTRIES = 1 << PTL3_BITS;
pub fn PTL3_INDEX(addr: usize) usize {
    return (addr >> PTL3_SHIFT) & (PTL3_ENTRIES - 1);
}

pub const PTL2_SHIFT = 21;
pub const PTL2_BITS = 9;
pub const PTL2_ENTRIES = 1 << PTL2_BITS;
pub fn PTL2_INDEX(addr: usize) usize {
    return (addr >> PTL2_SHIFT) & (PTL2_ENTRIES - 1);
}

pub const PTL1_SHIFT = 12;
pub const PTL1_BITS = 9;
pub const PTL1_ENTRIES = 1 << PTL1_BITS;
pub fn PTL1_INDEX(addr: usize) usize {
    return (addr >> PTL1_SHIFT) & (PTL1_ENTRIES - 1);
}

pub const PAGE_SIZE: usize = 1 << PTL1_SHIFT;
pub const PAGE_MASK: usize = ~(PAGE_SIZE - 1);
pub const PHYS_MASK: usize = 0x000FFFFFFFFFF000;

pub const PageTableEntry = packed struct {
    present: bool,
    writable: bool,
    user: bool,
    write_through: bool,
    cache_disable: bool,
    accesed: bool,
    dirty: bool,
    huge: bool,
    global: bool,
    shared: bool, // custom
    unused1: u2,
    phys: u40,
    ref_count: u7, // custom
    pk: u4,
    nx: bool,

    pub fn frameBase(self: PageTableEntry) usize {
        return self.phys << 12;
    }

    pub fn flags(self: PageTableEntry) usize {
        return @as(usize, @bitCast(self)) & ~PHYS_MASK;
    }

    pub fn ref(self: *PageTableEntry) void {
        assert(self.user);
        assert(self.ref_count != 0);
        self.ref_count += 1;
    }

    pub fn unref(self: *PageTableEntry) void {
        assert(self.user);
        self.ref_count -= 1;
        if (self.ref_count == 0) {
            mem.pmm.freeFrame(self.frameBase());
            self.clear();
        }
    }

    pub fn setFrameBase(self: *PageTableEntry, base: usize) void {
        assert((base & PHYS_MASK) == base);
        self.phys = @intCast(base >> 12);
    }

    pub fn setFlags(self: *PageTableEntry, flags_value: usize) void {
        assert((flags_value & ~PHYS_MASK) == flags_value);
        const self_usize: *usize = @ptrCast(self);
        self_usize.* = (self_usize.* & PHYS_MASK) | flags_value;
        // self.raw &= PHYS_MASK;
        // self.raw |= flags_value;
    }

    pub fn clear(self: *PageTableEntry) void {
        const self_usize: *usize = @ptrCast(self);
        self_usize.* = 0;
    }

    pub fn isPresent(self: PageTableEntry) bool {
        // Frames without Present but with Global are actually present as
        // prot none.
        return self.present or self.global;
    }

    pub fn setPresent(self: *PageTableEntry, value: bool) void {
        self.present = value;
    }

    pub fn isWritable(self: PageTableEntry) bool {
        return self.writable;
    }

    pub fn setWritable(self: *PageTableEntry, value: bool) void {
        self.writable = value;
    }

    pub fn isUser(self: PageTableEntry) bool {
        return self.user;
    }

    pub fn setUser(self: *PageTableEntry, value: bool) void {
        self.user = value;
    }

    pub fn isHuge(self: PageTableEntry) bool {
        return self.huge;
    }

    pub fn setHuge(self: *PageTableEntry, value: bool) void {
        self.huge = value;
    }

    pub fn isGlobal(self: PageTableEntry) bool {
        return self.global;
    }

    pub fn setGlobal(self: *PageTableEntry, value: bool) void {
        self.global = value;
    }

    pub fn isProtNone(self: PageTableEntry) bool {
        // Frames with no protections are marked as not present and global,
        // though they are actually present.
        return !self.present and self.global;
    }

    pub fn setProtNone(self: *PageTableEntry, value: bool) void {
        self.present = !value;
        self.global = value;
    }

    pub fn isShared(self: PageTableEntry) bool {
        return self.shared;
    }

    pub fn setShared(self: *PageTableEntry, value: bool) void {
        self.shared = value;
    }

    pub fn isNoExecute(self: PageTableEntry) bool {
        return self.nx;
    }

    pub fn setNoExecute(self: *PageTableEntry, value: bool) void {
        self.nx = value;
    }
};

// YOLO
pub const PageTableLevel2Entry = PageTableEntry;
pub const PageTableLevel3Entry = PageTableEntry;
pub const PageTableLevel4Entry = PageTableEntry;

comptime {
    assert(@sizeOf(PageTableEntry) == @sizeOf(usize));
    assert(@bitOffsetOf(PageTableEntry, "phys") == 12);
    assert(@bitOffsetOf(PageTableEntry, "ref_count") == 52);
}

pub const PageTable = struct {
    ptl4: RawType,

    const RawType = *[PTL4_ENTRIES]PageTableLevel4Entry;

    pub fn init(ptl4_paddr: usize) PageTable {
        return PageTable{
            .ptl4 = mem.pmm.physToVirt(RawType, ptl4_paddr),
        };
    }

    pub fn fromCurrent() PageTable {
        return init(x86.rdcr3());
    }

    pub fn load(self: *PageTable) void {
        x86.wrcr3(mem.pmm.virtToPhys(self.ptl4));
    }

    pub const MappingOptions = packed struct {
        writable: bool = false,
        user: bool = false,
        huge: bool = false,
        global: bool = false,
        protNone: bool = false,
        shared: bool = false,
        noExecute: bool = false,
        discardAlreadyMapped: bool = false,
    };

    pub const MappingError = mem.pmm.Error || error{AlreadyMapped};

    /// Map a virtual address to a physical address with given options.
    /// Can't return error.AlreadyMapped if options.discardAlreadyMapped is set.
    pub fn mapPage(self: *PageTable, virt: usize, phys: usize, options: MappingOptions) MappingError!void {
        log.debug("mapping 0x{x} to 0x{x}\n", .{ virt, phys });
        // Make sure addresses are aligned.
        assert(mem.isPageAligned(virt));
        assert(mem.isPageAligned(phys));

        // Ensure the PTE
        var pte = try self.ensurePTE(virt);

        // If PTE is already present, free it if we are said to. Otherwise
        // return error.
        if (pte.isPresent()) {
            if (options.discardAlreadyMapped) {
                mem.vmm.kernel_page_table.unrefFrame(pte.frameBase());
            } else {
                return MappingError.AlreadyMapped;
            }
        }

        // Set the given frame and options, and flush the TLB entry
        pte.setFrameBase(phys);
        mem.vmm.kernel_page_table.refFrame(phys);
        setOptionsToPTE(pte, options);
        x86.flush_tlb_entry(virt);

        log.debug("mapped 0x{x} to 0x{x}\n", .{ virt, phys });
    }

    pub const UnmappingError = error{NotMapped};

    /// Unmap a virtual address.
    pub fn unmapPage(self: *PageTable, virt: usize) UnmappingError!void {
        assert(mem.isPageAligned(virt));

        // Attempt to get the PTE. If it is not present, same error.
        const pte = self.getPTE(virt) orelse return UnmappingError.NotMapped;
        if (!pte.isPresent())
            return UnmappingError.NotMapped;

        // Free frame and clear PTE
        log.debug("unmapped 0x{x} (phys 0x{x})\n", .{ virt, pte.frameBase() });
        mem.vmm.kernel_page_table.unrefFrame(pte.frameBase());
        pte.clear();
        x86.flush_tlb_entry(virt);
    }

    pub const SetPermsError = error{NotMapped};

    /// Set page permissions, without altering other flags.
    pub fn setPagePerms(self: *PageTable, virt: usize, perms: mem.Perms) SetPermsError!void {
        assert(mem.isPageAligned(virt));

        // Attempt to get the PTE. If it is not present, same error.
        const pte = self.getPTE(virt) orelse return SetPermsError.NotMapped;
        if (!pte.isPresent())
            return UnmappingError.NotMapped;

        // Set given perms and flush the TLB entry associated with given page
        pte.setProtNone(perms.isNone());
        pte.setWritable(perms.write);
        pte.setNoExecute(!perms.exec);
        x86.flush_tlb_entry(virt);
    }

    pub fn isMapped(self: PageTable, virt: usize) bool {
        if (self.getPTE(virt)) |pte| {
            return pte.isPresent();
        }
        return false;
    }

    fn setOptionsToPTE(pte: *PageTableEntry, options: MappingOptions) void {
        // Make sure we don't ask for global and protNone at the same time, as
        // protNone uses the global bit.
        assert(!(options.global and options.protNone));

        // Set each flag. Don't set present if protNone.
        pte.setPresent(!options.protNone);
        pte.setWritable(options.writable);
        pte.setUser(options.user);
        pte.setHuge(options.huge);
        pte.setGlobal(options.global);
        pte.setProtNone(options.protNone);
        pte.setShared(options.shared);
        pte.setNoExecute(options.noExecute);
    }

    /// Get the PTE of a given page, allocating and mapping entries along the way.
    fn ensurePTE(self: *PageTable, page_vaddr: usize) mem.pmm.Error!*PageTableEntry {
        const ptl4_i = PTL4_INDEX(page_vaddr);
        const ptl3_i = PTL3_INDEX(page_vaddr);
        const ptl2_i = PTL2_INDEX(page_vaddr);
        const ptl1_i = PTL1_INDEX(page_vaddr);

        const ptl4 = self.ptl4;
        const ptl4_entry = &ptl4[ptl4_i];
        try ensureEntryPresent(ptl4_entry);

        const ptl3 = pageTablePointedBy(ptl4_entry);
        const ptl3_entry = &ptl3[ptl3_i];
        try ensureEntryPresent(ptl3_entry);

        const ptl2 = pageTablePointedBy(ptl3_entry);
        const ptl2_entry = &ptl2[ptl2_i];
        try ensureEntryPresent(ptl2_entry);

        const ptl1 = pageTablePointedBy(ptl2_entry);
        const ptl1_entry = &ptl1[ptl1_i];
        return ptl1_entry;
    }

    /// Get the PTE of a given page, or null if any entry along the way was
    /// not present.
    pub fn getPTE(self: PageTable, page_vaddr: usize) ?*PageTableEntry {
        const ptl4_i = PTL4_INDEX(page_vaddr);
        const ptl3_i = PTL3_INDEX(page_vaddr);
        const ptl2_i = PTL2_INDEX(page_vaddr);
        const ptl1_i = PTL1_INDEX(page_vaddr);

        const ptl4 = self.ptl4;
        const ptl4_entry = &ptl4[ptl4_i];
        if (!ptl4_entry.isPresent())
            return null;

        const ptl3 = pageTablePointedBy(ptl4_entry);
        const ptl3_entry = &ptl3[ptl3_i];
        if (!ptl3_entry.isPresent())
            return null;

        const ptl2 = pageTablePointedBy(ptl3_entry);
        const ptl2_entry = &ptl2[ptl2_i];
        if (!ptl2_entry.isPresent())
            return null;

        const ptl1 = pageTablePointedBy(ptl2_entry);
        const ptl1_entry = &ptl1[ptl1_i];
        return ptl1_entry;
    }

    /// Get the page table pointed by a PTE.
    fn pageTablePointedBy(entry: *PageTableEntry) RawType {
        return mem.pmm.physToVirt(RawType, entry.frameBase());
    }

    /// Allocate and map a PTE if it's not present.
    fn ensureEntryPresent(entry: *PageTableEntry) mem.pmm.Error!void {
        if (!entry.isPresent()) {
            const frame = try mem.pmm.allocFrame();
            entry.setFrameBase(frame);
            entry.setPresent(true);
            entry.setWritable(true);
            entry.setUser(true); // TODO: remove me and see what happens
            x86.flush_tlb_entry(mem.pmm.physToVirt(usize, frame));
            log.debug("mapping page table at 0x{x}\n", .{frame});
        }
    }

    pub fn clone(self: PageTable) !PageTable {
        const ptl4_paddr = try clonePageTable(4, self.ptl4);
        return PageTable.init(ptl4_paddr);
    }

    fn clonePageTable(comptime level: usize, table: RawType) mem.pmm.Error!usize {
        // TODO errdefer
        // TODO try set level comptime
        const page_table_frame = try mem.pmm.allocFrame();
        errdefer mem.pmm.freeFrame(page_table_frame);
        const copy = mem.pmm.physToVirt(RawType, page_table_frame);

        for (table, copy) |*entry, *entry_copy| {
            if (!entry.isPresent())
                continue;
            const frame = if (entry.isShared())
                entry.frameBase()
            else if (level > 1)
                try clonePageTable(level - 1, pageTablePointedBy(entry))
            else
                try mem.pmm.dupFrame(entry.frameBase());
            mem.vmm.kernel_page_table.refFrame(frame);
            entry_copy.setFrameBase(frame);
            entry_copy.setFlags(entry.flags());
        }

        return page_table_frame;
    }

    pub fn deinit(self: *PageTable) void {
        // TODO
        // deinitPageTable(4, self.ptl4);
        _ = self;
    }

    // This doesn't work yet
    fn deinitPageTable(level: usize, table: RawType) void {
        for (table) |*entry| {
            if (!entry.isPresent())
                continue;
            if (level == 1) {
                common.print("unrefing {x}\n", .{entry.frameBase()});
                mem.vmm.kernel_page_table.unrefFrame(entry.frameBase());
            } else {
                deinitPageTable(level - 1, pageTablePointedBy(entry));
            }
        }
        mem.vmm.kernel_page_table.unrefFrame(mem.pmm.virtToPhys(table));
    }
};

pub const KernelPageTable = struct {
    page_table: PageTable,

    pub fn init() KernelPageTable {
        const page_table = PageTable.fromCurrent();
        page_table.ptl4[PTL4_ENTRIES - 1].setShared(true);
        return KernelPageTable{
            .page_table = page_table,
        };
    }

    pub fn mapPage(self: *KernelPageTable, virt: usize, phys: usize, options: PageTable.MappingOptions) PageTable.MappingError!void {
        assert(mem.safe.isAddressInKernelRange(virt));
        return self.page_table.mapPage(virt, phys, options);
    }

    pub fn unmapPage(self: *KernelPageTable, virt: usize) PageTable.UnmappingError!void {
        assert(mem.safe.isAddressInKernelRange(virt));
        return self.page_table.unmapPage(virt);
    }

    fn getPhysmapPTE(self: KernelPageTable, frame: usize) ?*PageTableEntry {
        if (frame >= mem.pmm.memoryLength())
            return null;
        const virt = mem.pmm.physToVirt(usize, frame);
        const pte = self.page_table.getPTE(virt).?;
        assert(pte.frameBase() == frame);
        return pte;
    }

    pub fn refFrame(self: *KernelPageTable, frame: usize) void {
        const pte = self.getPhysmapPTE(frame) orelse return;
        pte.ref_count += 1;
    }

    pub fn unrefFrame(self: *KernelPageTable, frame: usize) void {
        const pte = self.getPhysmapPTE(frame) orelse return;
        assert(pte.ref_count > 0);
        pte.ref_count -= 1;
        if (pte.ref_count == 0) {
            mem.pmm.freeFrame(frame);
        }
    }

    // pub fn ensurePTE(self: *KernelPageTable, page_vaddr: usize) !*PageTableEntry {
    //     assert(page_vaddr >= LAST_PTL4_ENTRY_ADDR);
    //     return self.page_table.ensurePTE(page_vaddr);
    // }
};
