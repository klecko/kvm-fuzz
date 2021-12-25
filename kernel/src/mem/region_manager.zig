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

fn testingRegionManager() RegionManager {
    return RegionManager.init(std.testing.allocator, 0, 16);
}

fn expectRegionsEqual(expected: []const Region, region_manager: RegionManager) !void {
    try std.testing.expectEqualSlices(Region, expected, region_manager.regions.items);
}

test "setMapped join" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 1);
    try region_manager.setMapped(2, 3);
    try region_manager.setMapped(1, 2);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 3 },
    }, region_manager);
}

test "setMapped two separate" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 1);
    try region_manager.setMapped(2, 3);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 1 },
        Region{ .addr_start = 2, .addr_end = 3 },
    }, region_manager);
}

test "setMapped two separate inverse order" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(2, 3);
    try region_manager.setMapped(0, 1);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 1 },
        Region{ .addr_start = 2, .addr_end = 3 },
    }, region_manager);
}

test "setMapped expand region right" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 2);
    try region_manager.setMapped(2, 4);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 4 },
    }, region_manager);
}

test "setMapped expand region right + already mapped" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 2);
    try region_manager.setMapped(1, 3);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 3 },
    }, region_manager);
}

test "setMapped expand region left" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(2, 4);
    try region_manager.setMapped(0, 2);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 4 },
    }, region_manager);
}

test "setMapped expand region left + already mapped" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 3);
    try region_manager.setMapped(0, 2);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 3 },
    }, region_manager);
}

test "setMapped join many" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 2);
    try region_manager.setMapped(3, 4);
    try region_manager.setMapped(5, 6);
    try region_manager.setMapped(7, 8);
    try region_manager.setMapped(0, 8);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 8 },
    }, region_manager);
}

test "setMapped three separate" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 1);
    try region_manager.setMapped(4, 5);
    try region_manager.setMapped(2, 3);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 1 },
        Region{ .addr_start = 2, .addr_end = 3 },
        Region{ .addr_start = 4, .addr_end = 5 },
    }, region_manager);
}

test "setMapped double map whole region" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 1);
    try region_manager.setMapped(0, 1);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 1 },
    }, region_manager);
}

test "setMapped double map subregion" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 3);
    try region_manager.setMapped(1, 2);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 3 },
    }, region_manager);
}

test "setNotMapped shrink left" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 3);
    try region_manager.setNotMapped(1, 2);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 2, .addr_end = 3 },
    }, region_manager);
}

test "setNotMapped shrink left + not mapped" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 3);
    try region_manager.setNotMapped(0, 2);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 2, .addr_end = 3 },
    }, region_manager);
}

test "setNotMapped shrink right" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 2);
    try region_manager.setNotMapped(1, 2);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 1 },
    }, region_manager);
}

test "setNotMapped shrink right + not mapped" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 2);
    try region_manager.setNotMapped(1, 3);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 1 },
    }, region_manager);
}

test "setNotMapped split unmapping subregion" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 3);
    try region_manager.setNotMapped(1, 2);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 1 },
        Region{ .addr_start = 2, .addr_end = 3 },
    }, region_manager);
}

test "setNotMapped unmap region" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 2);
    try region_manager.setNotMapped(1, 2);
    try expectRegionsEqual(&.{}, region_manager);
}

test "setNotMapped unmap region + not mapped" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 2);
    try region_manager.setNotMapped(0, 3);
    try expectRegionsEqual(&.{}, region_manager);
}

test "setNotMapped unmap many" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 2);
    try region_manager.setMapped(3, 4);
    try region_manager.setMapped(5, 6);
    try region_manager.setMapped(7, 8);
    try region_manager.setNotMapped(0, 9);
    try expectRegionsEqual(&.{}, region_manager);
}

test "setNotMapped unmap some + shrink edges" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 2);
    try region_manager.setMapped(3, 4);
    try region_manager.setMapped(5, 6);
    try region_manager.setMapped(7, 9);
    try region_manager.setNotMapped(1, 8);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 0, .addr_end = 1 },
        Region{ .addr_start = 8, .addr_end = 9 },
    }, region_manager);
}

test "setNotMapped unmap single" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 2);
    try region_manager.setMapped(3, 4);
    try region_manager.setMapped(5, 6);
    try region_manager.setNotMapped(3, 4);
    try expectRegionsEqual(&.{
        Region{ .addr_start = 1, .addr_end = 2 },
        Region{ .addr_start = 5, .addr_end = 6 },
    }, region_manager);
}

test "findNotMapped before mapped region" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 2);
    const result = region_manager.findNotMapped(1);
    try std.testing.expectEqual(@as(?usize, 0), result);
}

test "findNotMapped after mapped region" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(0, 1);
    const result = region_manager.findNotMapped(1);
    try std.testing.expectEqual(@as(?usize, 1), result);
}

test "findNotMapped skip too small holes" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(1, 2);
    try region_manager.setMapped(3, 4);
    const result = region_manager.findNotMapped(2);
    try std.testing.expectEqual(@as(?usize, 4), result);
}

test "findNotMapped oom" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    try region_manager.setMapped(region_manager.total.addr_start, region_manager.total.addr_end);
    const result = region_manager.findNotMapped(1);
    try std.testing.expectEqual(@as(?usize, null), result);
}

test "findNotMapped almost oom" {
    var region_manager = testingRegionManager();
    defer region_manager.deinit();
    const almost_end = region_manager.total.addr_end - 1;
    try region_manager.setMapped(region_manager.total.addr_start, almost_end);
    const result = region_manager.findNotMapped(1);
    try std.testing.expectEqual(@as(?usize, almost_end), result);
}
