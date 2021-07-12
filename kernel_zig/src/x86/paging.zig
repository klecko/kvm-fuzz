usingnamespace @import("../common.zig");
const mem = @import("../mem/mem.zig");
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
    pub fn mapPage(self: *PageTable, virt: usize, phys: usize, options: MappingOptions) MappingError!void {
        // Make sure addresses are aligned.
        assert(mem.isPageAligned(virt));
        assert(mem.isPageAligned(phys));

        // Ensure the PTE
        var pte = try self.ensurePTE(virt);

        // If PTE is already present, free it if we are said to. Otherwise
        // return error.
        if (pte.isPresent()) {
            if (options.discardAlreadyMapped) {
                mem.pmm.freeFrame(pte.frameBase());
            } else {
                return MappingError.AlreadyMapped;
            }
        }

        // Set the given frame and options, and flush the TLB entry
        pte.setFrameBase(phys);
        setOptionsToPTE(pte, options);
        x86.flush_tlb_entry(virt);

        log.debug("mapped 0x{x} to 0x{x} {}\n", .{ virt, phys, options });
    }

    pub const UnmappingError = error{NotMapped};

    /// Unmap a virtual address.
    pub fn unmapPage(self: *PageTable, virt: usize) UnmappingError!void {
        assert(mem.isPageAligned(virt));

        // Attempt to get the PTE
        if (self.getPTE(virt)) |pte| {
            // If it's not present, return an error
            if (!pte.isPresent())
                return UnmappingError.NotMapped;

            // TODO: should we be freeing here?
            // Free frame and clear PTE
            mem.pmm.freeFrame(pte.frameBase());
            pte.clear();
            x86.flush_tlb_entry(virt);
            log.debug("unmapped 0x{x}\n", .{virt});
        } else {
            // Some page table which contains the PTE is not present, same error
            return UnmappingError.NotMapped;
        }
    }

    pub const SetPermsError = error{NotMapped};

    /// Set page permissions, without altering other flags.
    pub fn setPagePerms(self: *PageTable, virt: usize, perms: mem.Perms) SetPermsError!void {
        assert(mem.isPageAligned(virt));

        // Attempt to get the PTE
        if (self.getPTE(virt)) |pte| {
            // If it's not present, return an error
            if (!pte.isPresent())
                return UnmappingError.NotMapped;

            // Set given perms and flush the TLB entry associated with given page
            pte.setProtNone(perms.isNone());
            pte.setWritable(perms.write);
            pte.setNoExecute(!perms.exec);
            x86.flush_tlb_entry(virt);
        } else {
            // Some page table which contains the PTE is not present, same error
            return UnmappingError.NotMapped;
        }
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
    pub fn getPTE(self: *PageTable, page_vaddr: usize) ?*PageTableEntry {
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

    pub fn mapPage(self: *KernelPageTable, virt: usize, phys: usize, options: PageTable.MappingOptions) PageTable.MappingError!void {
        assert(mem.safe.isAddressInKernelRange(virt));
        return self.page_table.mapPage(virt, phys, options);
    }

    pub fn unmapPage(self: *KernelPageTable, virt: usize) PageTable.UnmappingError!void {
        assert(mem.safe.isAddressInKernelRange(virt));
        return self.page_table.unmapPage(virt);
    }

    // pub fn ensurePTE(self: *KernelPageTable, page_vaddr: usize) !*PageTableEntry {
    //     assert(page_vaddr >= LAST_PTL4_ENTRY_ADDR);
    //     return self.page_table.ensurePTE(page_vaddr);
    // }
};
