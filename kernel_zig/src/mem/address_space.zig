usingnamespace @import("../common.zig");
const mem = @import("mem.zig");
const x86 = @import("../x86/x86.zig");
const PageTable = x86.paging.PageTable;
const Allocator = std.mem.Allocator;

pub const Perms = packed struct {
    read: bool = false,
    write: bool = false,
    exec: bool = false,

    pub fn isNone(perms: Perms) bool {
        return !perms.read and !perms.write and !perms.exec;
    }
};

pub const AddressSpace = struct {
    allocator: *Allocator,
    page_table: PageTable,

    pub fn fromCurrent(allocator: *Allocator) AddressSpace {
        return AddressSpace{
            .allocator = allocator,
            .page_table = PageTable.fromCurrent(),
        };
    }

    pub fn load(self: *AddressSpace) void {
        self.page_table.load();
    }

    pub const MapFlags = packed struct {
        discardAlreadyMapped: bool = false,
        shared: bool = false,
    };

    fn checkRange(addr: usize, length: usize) !void {
        assert(mem.isPageAligned(addr));
        assert(mem.isPageAligned(length));
        assert(length != 0);
        if (!mem.safe.isRangeInUserRange(addr, length))
            return error.NotUserRange;
    }

    const MappingError = PageTable.MappingError || error{NotUserRange};
    pub fn mapRange(self: *AddressSpace, addr: usize, length: usize, perms: Perms, flags: MapFlags) MappingError!void {
        try checkRange(addr, length);

        // Attempt to allocate physical memory for the range
        const num_frames = @divExact(mem.alignPageForward(length), std.mem.page_size);
        var frames = try mem.pmm.allocFrames(self.allocator, num_frames);
        errdefer mem.pmm.freeFrames(frames);
        defer self.allocator.free(frames);

        // Get the mapping options acording to memory permissions and mapping flags
        const mapping_options = x86.paging.PageTable.MappingOptions{
            .writable = perms.write,
            .user = true,
            .protNone = perms.isNone(),
            .shared = flags.shared,
            .noExecute = !perms.exec,
            .discardAlreadyMapped = flags.discardAlreadyMapped,
        };

        // Map every page
        var i: usize = 0;
        var page_base: usize = addr;
        errdefer self.unmapRange(addr, page_base - addr) catch unreachable;
        while (i < num_frames) : ({
            i += 1;
            page_base += std.mem.page_size;
        }) {
            try self.page_table.mapPage(page_base, frames[i], mapping_options);
        }
    }

    pub fn mapRangeAnywhere(self: *AddressSpace, length: usize, perms: Perms, flags: MapFlags) MappingError!usize {
        if (self.findFreeRange(length)) |range_base_addr| {
            try mapRange(range_base_addr, length, perms, options);
            return range_base_addr;
        }
        return MappingError.OutOfMemory;
    }

    // TODO
    fn findFreeRange(self: *AddressSpace, length: usize) ?usize {}

    const UnmappingError = PageTable.UnmappingError || error{NotUserRange};

    pub fn unmapRange(self: *AddressSpace, addr: usize, length: usize) UnmappingError!void {
        try checkRange(addr, length);

        // Unmap every page
        const addr_end = addr + length;
        var page_base: usize = addr;
        while (page_base < addr_end) : (page_base += std.mem.page_size) {
            try self.page_table.unmapPage(page_base);
        }
    }

    const SetPermsError = PageTable.SetPermsError || error{NotUserRange};

    pub fn setRangePerms(self: *AddressSpace, addr: usize, length: usize, perms: Perms) SetPermsError!void {
        try checkRange(addr, length);

        // Set permissions for each page
        const addr_end = addr + length;
        var page_base: usize = addr;
        while (page_base < addr_end) : (page_base += std.mem.page_size) {
            try self.page_table.setPagePerms(page_base, perms);
        }
    }
};
