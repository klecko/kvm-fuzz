usingnamespace @import("../common.zig");
const pmm = @import("../mem/pmm.zig");
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
pub const LAST_PTL4_ENTRY_ADDR: usize = 0xFFFFFF8000000000;

pub fn isPageAligned(addr: usize) bool {
    return (addr & PAGE_MASK) == addr;
}

pub const PageTableEntry = struct {
    raw: usize,

    // zig fmt: off
    pub const Flags = enum(usize) {
        Present   = (1 << 0),
        ReadWrite = (1 << 1),
        User      = (1 << 2),
        Accessed  = (1 << 5),
        Dirty     = (1 << 6),
        Huge      = (1 << 7),
        Global    = (1 << 8),
        Shared    = (1 << 9),
        NoExecute = (1 << 63)
    };
    // zig fmt: on

    pub fn frameBase(self: PageTableEntry) usize {
        return self.raw & PHYS_MASK;
    }

    pub fn flags(self: PageTableEntry) usize {
        return self.raw & ~PHYS_MASK;
    }

    pub fn setFrameBase(self: *PageTableEntry, base: usize) void {
        assert((base & PHYS_MASK) == base);
        self.raw &= ~PHYS_MASK;
        self.raw |= base;
    }

    pub fn setFlags(self: *PageTableEntry, flags_value: usize) void {
        assert((flags_value & ~PHYS_MASK) == flags_value);
        self.raw &= PHYS_MASK;
        self.raw |= flags_value;
    }

    pub fn clear(self: *PageTableEntry) void {
        self.raw = 0;
    }

    // The only reason we don't expose hasFlag() and setFlag() and instead we
    // do wrappers for every flag is because that would allow calling
    // hasFlag(.Present), while we want it to be isPresent() for handling
    // frames with prot none correctly.
    fn hasFlag(self: PageTableEntry, flag: Flags) bool {
        return (self.raw & @enumToInt(flag)) != 0;
    }

    fn setFlag(self: *PageTableEntry, flag: Flags, value: bool) void {
        if (value) {
            self.raw |= @enumToInt(flag);
        } else {
            self.raw &= ~@enumToInt(flag);
        }
    }
    pub fn isPresent(self: PageTableEntry) bool {
        // Frames without Present but with Global are actually present as
        // prot none.
        return self.hasFlag(.Present) or self.hasFlag(.Global);
    }

    pub fn setPresent(self: *PageTableEntry, value: bool) void {
        self.setFlag(.Present, value);
    }

    pub fn isWritable(self: PageTableEntry) bool {
        return self.hasFlag(.ReadWrite);
    }

    pub fn setWritable(self: *PageTableEntry, value: bool) void {
        self.setFlag(.ReadWrite, value);
    }

    pub fn isUser(self: PageTableEntry) bool {
        return self.hasFlag(.User);
    }

    pub fn setUser(self: *PageTableEntry, value: bool) void {
        self.setFlag(.User, value);
    }

    pub fn isHuge(self: PageTableEntry) bool {
        return self.hasFlag(.Huge);
    }

    pub fn setHuge(self: *PageTableEntry, value: bool) void {
        self.setFlag(.Huge, value);
    }

    pub fn isGlobal(self: PageTableEntry) bool {
        return self.hasFlag(.Global);
    }

    pub fn setGlobal(self: *PageTableEntry, value: bool) void {
        self.setFlag(.Global, value);
    }

    pub fn isProtNone(self: PageTableEntry) bool {
        // Frames with no protections are marked as not present and global,
        // though they are actually present.
        return !self.hasFlag(.Present) and self.hasFlag(.Global);
    }

    pub fn setProtNone(self: *PageTableEntry, value: bool) void {
        self.setFlag(.Present, !value);
        self.setFlag(.Global, value);
    }

    pub fn isShared(self: PageTableEntry) bool {
        return self.hasFlag(.Shared);
    }

    pub fn setShared(self: *PageTableEntry, value: bool) void {
        self.setFlag(.Shared, value);
    }

    pub fn isNoExecute(self: PageTableEntry) bool {
        return self.hasFlag(.NoExecute);
    }

    pub fn setNoExecute(self: *PageTableEntry, value: bool) void {
        self.setFlag(.NoExecute, value);
    }
};

// YOLO
pub const PageTableLevel2Entry = PageTableEntry;
pub const PageTableLevel3Entry = PageTableEntry;
pub const PageTableLevel4Entry = PageTableEntry;

comptime {
    assert(@sizeOf(PageTableEntry) == @sizeOf(usize));
}

pub const PageTable = struct {
    ptl4: RawType,

    const RawType = *[PTL4_ENTRIES]PageTableLevel4Entry;

    pub fn init(ptl4_paddr: usize) PageTable {
        return PageTable{
            .ptl4 = pmm.physToVirt(RawType, ptl4_paddr),
            // .ptl4 = pmm.physToVirt(@typeInfo(PageTable).Struct.fields[0].field_type, ptl4_paddr),
        };
    }

    pub const MappingOptions = struct {
        writable: bool = false,
        user: bool = false,
        huge: bool = false,
        global: bool = false,
        protNone: bool = false,
        shared: bool = false,
        noExecute: bool = false,
    };

    pub fn mapPage(self: *PageTable, virt: usize, phys: usize, options: MappingOptions) !void {
        // Make sure we don't ask for global and protNone at the same time, as
        // protNone uses the global bit. Also make sure addresses are aligned.
        assert(!(options.global and options.protNone));
        assert(isPageAligned(virt));
        assert(isPageAligned(phys));

        log.debug("mapping 0x{x} to 0x{x}\n", .{ virt, phys });

        // Ensure the PTE
        var pte = try self.ensurePTE(virt);

        // Set the given frame and set each flag. Don't set present if protNone.
        pte.setFrameBase(phys);
        pte.setPresent(options.protNone);
        pte.setWritable(options.writable);
        pte.setUser(options.user);
        pte.setHuge(options.huge);
        pte.setGlobal(options.global);
        pte.setProtNone(options.protNone);
        pte.setShared(options.protNone);
        pte.setNoExecute(options.noExecute);

        // Flush the TLB entry associated with given page
        x86.flush_tlb_entry(virt);
    }

    pub fn unmapPage(self: *PageTable, virt: usize) !void {
        assert(isPageAligned(virt));

        var pte = try self.ensurePTE(virt);
        assert(pte.isPresent());
        pmm.freeFrame(pte.frameBase());
        pte.clear();
        x86.flush_tlb_entry(virt);
        log.debug("unmapped 0x{x}\n", .{virt});
    }

    fn ensurePTE(self: *PageTable, page_vaddr: usize) !*PageTableEntry {
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

    fn pageTablePointedBy(entry: *PageTableEntry) RawType {
        return pmm.physToVirt(RawType, entry.frameBase());
    }

    fn ensureEntryPresent(entry: *PageTableEntry) !void {
        if (!entry.isPresent()) {
            const frame = try pmm.allocFrame();
            entry.setFrameBase(frame);
            entry.setPresent(true);
            entry.setWritable(true);
            entry.setUser(true);
            x86.flush_tlb_entry(pmm.physToVirt(usize, frame));
        }
    }
};

pub const KernelPageTable = struct {
    page_table: PageTable,

    pub fn init() KernelPageTable {
        return KernelPageTable{
            .page_table = PageTable.init(x86.rdcr3()),
        };
    }

    pub fn mapPage(self: *KernelPageTable, virt: usize, phys: usize, options: PageTable.MappingOptions) !void {
        // assert(virt >= LAST_PTL4_ENTRY_ADDR);
        return self.page_table.mapPage(virt, phys, options);
    }

    pub fn unmapPage(self: *KernelPageTable, virt: usize) !void {
        // assert(virt >= LAST_PTL4_ENTRY_ADDR);
        return self.page_table.unmapPage(virt);
    }

    // pub fn ensurePTE(self: *KernelPageTable, page_vaddr: usize) !*PageTableEntry {
    //     assert(page_vaddr >= LAST_PTL4_ENTRY_ADDR);
    //     return self.page_table.ensurePTE(page_vaddr);
    // }
};
