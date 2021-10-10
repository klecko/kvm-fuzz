usingnamespace @import("../common.zig");
const hypercalls = @import("../hypercalls.zig");
const mem = @import("../mem/mem.zig");
const linux = @import("../linux.zig");
const fs = @import("fs.zig");
const Allocator = std.mem.Allocator;
const log = std.log.scoped(.FileManager);

var file_contents: std.StringHashMap([]u8) = undefined;

/// For each file, get its filename and length and allocate a buffer for its
/// content. Insert the filename and the buffer into file_contents, and submit
/// the address of the buffer and the address of the length to the hypervisor,
/// which will write to them.
pub fn init(allocator: *Allocator, num_files: usize) void {
    file_contents = std.StringHashMap([]u8).init(allocator);

    // Temporary buffer for the filename
    var filename_tmp: [linux.PATH_MAX]u8 = undefined;

    // TODO: this might not work because pointers are changed while inserting
    // items
    var i: usize = 0;
    while (i < num_files) : (i += 1) {
        // Get the filename into the tmp buffer, calculate its length,
        // allocate a buffer and copy the filename.
        hypercalls.getFileName(i, &filename_tmp);
        const filename_len = std.mem.indexOfScalar(u8, &filename_tmp, 0).?;
        var filename = allocator.alloc(u8, filename_len) catch unreachable;
        std.mem.copy(u8, filename, filename_tmp[0..filename_len]);

        // Get the file size, allocate a buffer, insert it into file_contents
        // and submit buf and length pointers to the hypervisor, which will
        // fill the buffer with the file content.
        const size = hypercalls.getFileLen(i);
        var buf = allocator.alloc(u8, size) catch unreachable;
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

pub fn exists(filename: []const u8) bool {
    return file_contents.contains(filename);
}

pub fn fileContent(filename: []const u8) ?[]u8 {
    return file_contents.get(filename);
}

const OpenError = Allocator.Error || error{FileNotFound};

/// Open a regular file
pub fn open(
    allocator: *Allocator,
    filename: []const u8,
    flags: i32,
) OpenError!*fs.FileDescription {
    const file_content = fileContent(filename) orelse {
        log.warn("attempt to open unknown file '{s}'\n", .{filename});
        return OpenError.FileNotFound;
    };
    const file = try fs.FileDescriptionRegular.create(allocator, file_content, flags);
    return &file.desc;
}

pub fn openStdin(allocator: *Allocator) Allocator.Error!*fs.FileDescription {
    const stdin = try fs.FileDescriptionStdin.create(allocator);
    return &stdin.desc;
}

pub fn openStdout(allocator: *Allocator) Allocator.Error!*fs.FileDescription {
    const stdout = try fs.FileDescriptionStdout.create(allocator);
    return &stdout.desc;
}

pub fn openStderr(allocator: *Allocator) Allocator.Error!*fs.FileDescription {
    const stderr = try fs.FileDescriptionStderr.create(allocator);
    return &stderr.desc;
}

pub fn openSocket(
    allocator: *Allocator,
    socket_type: fs.FileDescriptionSocket.SocketType,
) Allocator.Error!*fs.FileDescription {
    const buf = fileContent("input") orelse {
        log.alert("openSocket but there's no file named 'input', returning as if OOM", .{});
        return Allocator.Error.OutOfMemory;
    };
    const socket = try fs.FileDescriptionSocket.create(allocator, buf, socket_type);
    return &socket.desc;
}

/// Perform stat on a file
pub fn stat(filename: []const u8, stat_ptr: mem.safe.UserPtr(*linux.stat)) !void {
    // Use the pointer to the buffer as inode, as that's unique for each file.
    const file_content = fileContent(filename) orelse {
        log.warn("attempt to stat unknown file '{s}'\n", .{filename});
        return error.FileNotFound;
    };
    return fs.statRegular(stat_ptr, file_content.len, @ptrToInt(file_content.ptr));
}
