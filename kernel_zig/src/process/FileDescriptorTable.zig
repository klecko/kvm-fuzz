usingnamespace @import("common.zig");
const fs = @import("../fs/fs.zig");
const utils = @import("../utils/utils.zig");
const Allocator = std.mem.Allocator;
const FileDescriptorTable = @This();

table: HashMap,

ref: RefCounter,

const HashMap = std.AutoHashMap(linux.fd_t, *fs.FileDescription);
const RefCounter = utils.RefCounter(FileDescriptorTable);

fn destroy(ref: *RefCounter) void {
    const self = @fieldParentPtr(FileDescriptorTable, "ref", ref);

    // Unref every FileDescription in the table
    var iter = self.table.valueIterator();
    while (iter.next()) |file_ptr| {
        file_ptr.*.ref.unref();
    }

    // Deinit the table and free the object
    self.table.deinit();
    self.ref.allocator.destroy(self);
}

pub fn createDefault(allocator: *Allocator) !*FileDescriptorTable {
    // Allocate the file descriptor table and initialize it
    const ret = try allocator.create(FileDescriptorTable);
    errdefer allocator.destroy(ret);
    ret.* = FileDescriptorTable{
        .table = HashMap.init(allocator),
        .ref = RefCounter.init(allocator, destroy),
    };
    errdefer ret.table.deinit();

    // Open the standard files
    const stdin = try fs.file_manager.openStdin(allocator);
    errdefer stdin.ref.unref();
    const stdout = try fs.file_manager.openStdout(allocator);
    errdefer stdout.ref.unref();
    const stderr = try fs.file_manager.openStderr(allocator);
    errdefer stderr.ref.unref();

    // Insert the files in the table
    try ret.table.put(linux.STDIN_FILENO, stdin);
    try ret.table.put(linux.STDOUT_FILENO, stdout);
    try ret.table.put(linux.STDERR_FILENO, stderr);

    return ret;
}
