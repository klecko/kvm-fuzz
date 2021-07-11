usingnamespace @import("../common.zig");
const hypercalls = @import("../hypercalls.zig");
const mem = @import("../mem/mem.zig");
const page_allocator = mem.heap.page_allocator;
const log = std.log.scoped(.FileManager);
const linux = @import("../linux.zig");

var file_contents: std.StringHashMap([]u8) = undefined;

/// For each file, get its filename and length and allocate a buffer for its
/// content. Insert the filename and the buffer into file_contents, and submit
/// the address of the buffer and the address of the length to the hypervisor,
/// which will write to them.
pub fn init(num_files: usize) void {
    file_contents = std.StringHashMap([]u8).init(page_allocator);

    // Temporary buffer for the filename
    var filename_tmp: [linux.PATH_MAX]u8 = undefined;

    var i: usize = 0;
    while (i < num_files) : (i += 1) {
        // Get the filename into the tmp buffer, calculate its length,
        // allocate a buffer and copy the filename.
        hypercalls.getFileName(i, &filename_tmp);
        const filename_len = std.mem.indexOfScalar(u8, &filename_tmp, 0).?;
        var filename = page_allocator.alloc(u8, filename_len) catch unreachable;
        std.mem.copy(u8, filename, filename_tmp[0..filename_len]);

        // Get the file size, allocate a buffer, insert it into file_contents
        // and submit buf and length pointers to the hypervisor, which will
        // fill the buffer with the file content.
        const size = hypercalls.getFileLen(i);
        var buf = page_allocator.alloc(u8, size) catch |err| {
            panic("{} trying to allocate file content\n", .{err});
        };
        file_contents.put(filename, buf) catch unreachable;
        const length_ptr = &file_contents.getPtr(filename).?.*.len;
        hypercalls.submitFilePointers(i, buf.ptr, length_ptr);
    }

    log.debug("Files: {}\n", .{file_contents.count()});
    var iter = file_contents.iterator();
    while (iter.next()) |entry| {
        log.debug("\tFile '{s}', length {}\n", .{ entry.key_ptr.*, entry.value_ptr.*.len });
    }

    log.debug("File Manager initialized\n", .{});
}

pub fn existsFile(filename: []const u8) bool {
    return file_contents.contains(filename);
}

pub fn fileContent(filename: []const u8) ?[]u8 {
    return file_contents.get(filename);
}
