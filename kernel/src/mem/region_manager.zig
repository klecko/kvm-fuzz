const std = @import("std");
const assert = std.debug.assert;
const common = @import("../common.zig");
const panic = common.panic;
const PageTable = @import("../x86/x86.zig").paging.PageTable;
const Allocator = std.mem.Allocator;

pub const Region = struct {
    addr_start: usize,
    addr_end: usize,
};

pub const RegionManager = struct {
    // The total region of memory. Regions in `regions` will be contained in
    // this range.
    total: Region,

    /// Array of regions ordered by addr_start
    regions: std.ArrayList(Region),

    pub fn initCheckNotMapped(
        allocator: Allocator,
        addr_start: usize,
        addr_end: usize,
        page_table: PageTable,
    ) RegionManager {
        // Make sure the range is not mapped
        var page_base: usize = addr_start;
        while (page_base < addr_end) : (page_base += std.mem.page_size) {
            if (page_table.isMapped(page_base)) {
                panic("addr {x} is mapped\n", .{page_base});
            }
        }

        return init(allocator, addr_start, addr_end);
    }

    // This is not public because it assumes the range is not mapped at all, so
    // it should be called from `initCheckNotMapped`.
    fn init(allocator: Allocator, addr_start: usize, addr_end: usize) RegionManager {
        return RegionManager{
            .total = Region{ .addr_start = addr_start, .addr_end = addr_end },
            .regions = std.ArrayList(Region).init(allocator),
        };
    }

    pub fn deinit(self: RegionManager) void {
        self.regions.deinit();
    }

    fn regionInsideTotal(self: RegionManager, addr_start: usize, addr_end: usize) ?Region {
        const reg = Region{
            .addr_start = std.math.max(addr_start, self.total.addr_start),
            .addr_end = std.math.min(addr_end, self.total.addr_end),
        };
        return if (reg.addr_end > reg.addr_start) reg else null;
    }

    pub fn setMapped(self: *RegionManager, addr_start: usize, addr_end: usize) !void {
        if (self.regionInsideTotal(addr_start, addr_end)) |reg| {
            return self.setMappedRegionInsideTotal(reg.addr_start, reg.addr_end);
        }
    }

    fn setMappedRegionInsideTotal(self: *RegionManager, addr_start: usize, addr_end: usize) !void {
        assert(addr_start >= self.total.addr_start);
        assert(addr_end <= self.total.addr_end);
        assert(addr_end > addr_start);
        var expanding_reg: ?*Region = null;

        // Iterate regions we overlap with
        var i: usize = 0;
        while (i < self.regions.items.len) {
            var region = &self.regions.items[i];

            // Check if we've finished
            if (addr_end < region.addr_start)
                break;

            // If they don't overlap, continue
            if (addr_start > region.addr_end) {
                i += 1;
                continue;
            }

            // There are 4 cases, comparing addr_start vs region.addr_start
            // and addr_end vs region.addr_end. In each case we must differentiate
            // between having already an expanding region (so we expand it and
            // remove current region) or not (so we expand current region and
            // set it as expanding region).
            // _____ is `region`, and ...... is the region [addr_start, addr_end]
            // or `expanding_reg`.
            if (addr_start < region.addr_start) {
                if (addr_end < region.addr_end) {
                    //   ________
                    // ........
                    if (expanding_reg) |reg| {
                        reg.addr_end = region.addr_end;
                    } else {
                        region.addr_start = addr_start;
                    }
                } else {
                    //   ________
                    // .............
                    if (expanding_reg) |_| {
                        // Do nothing
                    } else {
                        region.addr_start = addr_start;
                        region.addr_end = addr_end;
                    }
                }
            } else {
                // In these cases there can't be an expanding region yet
                assert(expanding_reg == null);
                if (addr_end < region.addr_end) {
                    // _____________
                    //   ........
                    // Do nothing
                } else {
                    // ________
                    //   ........
                    region.addr_end = addr_end;
                }
            }

            if (expanding_reg == null) {
                expanding_reg = region;
                i += 1;
            } else {
                _ = self.regions.orderedRemove(i);
            }
        }

        // It doesn't overlap with any region, just insert it
        if (expanding_reg == null) {
            try self.regions.insert(i, Region{ .addr_start = addr_start, .addr_end = addr_end });
        }
    }

    pub fn setNotMapped(self: *RegionManager, addr_start: usize, addr_end: usize) !void {
        if (self.regionInsideTotal(addr_start, addr_end)) |reg| {
            return self.setNotMappedRegionInsideTotal(reg.addr_start, reg.addr_end);
        }
    }

    fn setNotMappedRegionInsideTotal(self: *RegionManager, addr_start: usize, addr_end: usize) !void {
        assert(addr_start >= self.total.addr_start);
        assert(addr_end <= self.total.addr_end);

        // Iterate regions we overlap with
        var i: usize = 0;
        while (i < self.regions.items.len) {
            var region = &self.regions.items[i];

            // Check if we've finished
            if (addr_end < region.addr_start)
                break;

            // If they don't overlap, continue
            if (addr_start > region.addr_end) {
                i += 1;
                continue;
            }

            // As in setMapped, there can be 4 cases comparing addr_start
            // and addr_end. We include equality in this first check because
            // we want to remove regions when they have the same addr_start.
            // Otherwise we would be left with 0-length ranges like [addr, addr].
            if (addr_start <= region.addr_start) {
                if (addr_end < region.addr_end) {
                    //   ________
                    // ........
                    region.addr_start = addr_end;
                    i += 1;
                } else {
                    //   ________
                    // .............
                    _ = self.regions.orderedRemove(i);
                }
            } else {
                if (addr_end < region.addr_end) {
                    // _____________
                    //   ........
                    // Split current region
                    const new_region = Region{ .addr_start = addr_end, .addr_end = region.addr_end };
                    try self.regions.insert(i + 1, new_region);
                    region.addr_end = addr_start;
                    i += 2;
                } else {
                    // ________
                    //   ........
                    region.addr_end = addr_start;
                    i += 1;
                }
            }
        }
    }

    pub fn findNotMapped(self: RegionManager, length: usize) ?usize {
        var not_mapped_start: usize = self.total.addr_start;
        for (self.regions.items) |region| {
            const length_not_mapped = region.addr_start - not_mapped_start;
            if (length_not_mapped >= length) {
                return not_mapped_start;
            }
            not_mapped_start = region.addr_end;
        }

        // Last not mapped region (after every mapped region)
        const length_not_mapped = self.total.addr_end - not_mapped_start;
        if (length_not_mapped >= length) {
            return not_mapped_start;
        }

        return null;
    }
};
