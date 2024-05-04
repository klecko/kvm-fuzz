const std = @import("std");
const assert = std.debug.assert;
const common = @import("../common.zig");
const TODO = common.TODO;
const mem = @import("../mem/mem.zig");
const linux = @import("../linux.zig");
const fs = @import("fs.zig");
const build_options = @import("build_options");
const utils = @import("../utils/utils.zig");
const log = std.log.scoped(.file_description);
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;
const Allocator = std.mem.Allocator;

pub fn statRegular(
    stat_ptr: UserPtr(*linux.Stat),
    fileSize: usize,
    inode: linux.ino_t,
) mem.safe.Error!void {
    // This structure is built at compile time, so the code generated for this
    // function is just a memcpy, some writes for the undefined values that
    // differ for each file, and a call to copyToUserSingle.
    // zig fmt: off
    const regular_st_base = comptime linux.Stat{
        .dev         = 2052,
        .ino         = undefined,
        .nlink       = 1,
        .mode        = 0o100664,
        .uid         = 0,
        .gid         = 0,
        .__pad0      = undefined,
        .rdev        = 0,
        .size        = undefined,
        .blksize     = std.mem.page_size,
        .blocks      = undefined,
        .atim        = .{
            .tv_sec  = 1615575193,
            .tv_nsec = 228169446,
        },
        .mtim        = .{
            .tv_sec  = 1596888770,
            .tv_nsec = 0,
        },
        .ctim        = .{
            .tv_sec  = 1612697533,
            .tv_nsec = 117084367,
        },
        .__unused = undefined,
    };
    // zig fmt: on

    var st = regular_st_base;
    st.ino = inode;
    st.size = @intCast(fileSize);
    st.blocks = @intCast(fileSize / 512 + 1);
    try mem.safe.copyToUserSingle(linux.Stat, stat_ptr, &st);
}

pub fn statStdin(stat_ptr: UserPtr(*linux.Stat)) mem.safe.Error!void {
    // Here it's just the call to copyToUserSingle.
    // zig fmt: off
    const stdin_stat = comptime linux.Stat{
        .dev         = 24,
        .ino         = 15,
        .nlink       = 1,
        .mode        = 0o20620,
        .uid         = 0,
        .gid         = 0,
        .__pad0      = undefined,
        .rdev        = 34827,
        .size        = 0,
        .blksize     = 1024,
        .blocks      = 0,
        .atim        = .{
            .tv_sec  = 0,
            .tv_nsec = 0,
        },
        .mtim        = .{
            .tv_sec  = 0,
            .tv_nsec = 0,
        },
        .ctim        = .{
            .tv_sec  = 0,
            .tv_nsec = 0,
        },
        .__unused = undefined,
    };
    // zig fmt: on

    try mem.safe.copyToUserSingle(linux.Stat, stat_ptr, &stdin_stat);
}

pub fn statStdout(stat_ptr: UserPtr(*linux.Stat)) mem.safe.Error!void {
    // zig fmt: off
    const stdout_stat = comptime linux.Stat{
        .dev         = 22,
        .ino         = 6,
        .nlink       = 1,
        .mode        = 0o20620,
        .uid         = 0,
        .gid         = 0,
        .__pad0      = undefined,
        .rdev        = 34819,
        .size        = 0,
        .blksize     = 1024,
        .blocks      = 0,
        .atim        = .{
            .tv_sec  = 0,
            .tv_nsec = 0,
        },
        .mtim        = .{
            .tv_sec  = 0,
            .tv_nsec = 0,
        },
        .ctim        = .{
            .tv_sec  = 0,
            .tv_nsec = 0,
        },
        .__unused = undefined,
    };
    // zig fmt: on

    try mem.safe.copyToUserSingle(linux.Stat, stat_ptr, &stdout_stat);
}

pub const FileDescription = struct {
    /// Pointer to file content
    buf: []const u8,

    /// Flags specified when calling open (O_RDONLY, O_RDWR...)
    flags: linux.O,

    /// Cursor offset
    offset: usize = 0,

    // File operations
    statFn: *const fn (self: *FileDescription, stat_ptr: UserPtr(*linux.Stat)) mem.safe.Error!void,
    readFn: *const fn (self: *FileDescription, buf: UserSlice([]u8)) ReadError!usize,
    writeFn: *const fn (self: *FileDescription, buf: UserSlice([]const u8)) mem.safe.Error!usize,

    /// Reference counter. It must free the whole object this FileDescription
    /// belongs to, not just the FileDescription.
    ref: RefCounter,

    is_socket: bool = false,

    const ReadError = mem.safe.Error || error{NotConnected};
    const RefCounter = utils.RefCounter(u16, FileDescription);
    const O_ACCMODE = 3;

    pub fn stat(self: *FileDescription, stat_ptr: UserPtr(*linux.Stat)) mem.safe.Error!void {
        return self.statFn(self, stat_ptr);
    }

    pub fn read(self: *FileDescription, buf: UserSlice([]u8)) ReadError!usize {
        return self.readFn(self, buf);
    }

    pub fn write(self: *FileDescription, buf: UserSlice([]const u8)) mem.safe.Error!usize {
        return self.writeFn(self, buf);
    }

    pub fn isReadable(self: *const FileDescription) bool {
        const access_mode = self.flags.ACCMODE;
        return (access_mode == .RDONLY) or (access_mode == .RDWR);
    }

    pub fn isWritable(self: *const FileDescription) bool {
        const access_mode = self.flags.ACCMODE;
        return (access_mode == .WRONLY) or (access_mode == .RDWR);
    }

    pub fn isOffsetPastEnd(self: *const FileDescription) bool {
        return self.offset >= self.buf.len;
    }

    pub fn size(self: *const FileDescription) usize {
        return self.buf.len;
    }

    pub fn moveOffset(self: *FileDescription, increment: usize) usize {
        // Check if offset is currently past end
        if (self.isOffsetPastEnd())
            return 0;

        // Reduce increment if there is not enough space available
        const ret = if (self.offset + increment < self.buf.len)
            increment
        else
            self.buf.len - self.offset;

        // Update offset
        self.offset += ret;
        return ret;
    }

    pub fn socket(self: *FileDescription) ?*FileDescriptionSocket {
        return if (self.is_socket)
            @fieldParentPtr("desc", self)
        else
            null;
    }
};

pub const FileDescriptionRegular = struct {
    desc: FileDescription,

    pub fn create(allocator: Allocator, buf: []const u8, flags: linux.O) Allocator.Error!*FileDescriptionRegular {
        // In this case we can avoid giving a destroy function to the RefCounter
        // because a FileDescriptionRegular is just a FileDescription. We would
        // have to do it if we added more fields, as in FileDescriptionStdin.
        const ret = try allocator.create(FileDescriptionRegular);
        ret.* = FileDescriptionRegular{
            .desc = FileDescription{
                .buf = buf,
                .flags = flags,
                .statFn = stat,
                .readFn = read,
                .writeFn = write,
                .ref = FileDescription.RefCounter.init(allocator, null),
            },
        };
        return ret;
    }
    comptime {
        assert(@sizeOf(FileDescriptionRegular) == @sizeOf(FileDescription));
    }

    fn stat(desc: *FileDescription, stat_ptr: UserPtr(*linux.Stat)) mem.safe.Error!void {
        // Use the pointer to the buffer as inode, as that's unique for each file.
        return statRegular(stat_ptr, desc.buf.len, @intFromPtr(desc.buf.ptr));
    }

    fn read(desc: *FileDescription, buf: UserSlice([]u8)) mem.safe.Error!usize {
        assert(desc.isReadable());

        // We must take care of this here, as slicing OOB is UB even when the
        // length is 0.
        if (desc.isOffsetPastEnd())
            return 0;

        const prev_offset = desc.offset;
        const length_moved = desc.moveOffset(buf.len());
        const src_slice = desc.buf[prev_offset .. prev_offset + length_moved];
        try mem.safe.copyToUser(u8, buf.sliceTo(src_slice.len), src_slice);
        return length_moved;
    }

    fn write(desc: *FileDescription, buf: UserSlice([]const u8)) mem.safe.Error!usize {
        _ = desc;
        _ = buf;
        TODO();
    }
};

pub const FileDescriptionStdin = struct {
    desc: FileDescription,
    input_opened: bool,

    pub fn create(allocator: Allocator) Allocator.Error!*FileDescriptionStdin {
        const ret = try allocator.create(FileDescriptionStdin);
        ret.* = FileDescriptionStdin{
            .desc = FileDescription{
                .buf = &[_]u8{},
                .flags = .{ .ACCMODE = .RDWR },
                .statFn = stat,
                .readFn = read,
                .writeFn = write,
                .ref = FileDescription.RefCounter.init(allocator, destroy),
            },
            .input_opened = false,
        };
        return ret;
    }

    // We must provide this function because we don't want to free desc, but self.
    // In this case they don't have the same size, as happens with Regular or
    // Stdout, so we must do it.
    fn destroy(desc: *FileDescription) void {
        const self: *FileDescriptionStdin = @fieldParentPtr("desc", desc);
        self.desc.ref.allocator.destroy(self);
    }

    fn stat(desc: *FileDescription, stat_ptr: UserPtr(*linux.Stat)) mem.safe.Error!void {
        _ = desc;
        return statStdin(stat_ptr);
    }

    fn read(desc: *FileDescription, buf: UserSlice([]u8)) mem.safe.Error!usize {
        // Guest is trying to read from stdin. Let's do a little hack here.
        // Assuming it's expecting to read from input file, let's set that input
        // file as our buffer, and read from there as a regular file. We can't
        // do this at the beginning, as we wouldn't get the real size from the
        // hypervisor when it updated the input file.
        // TODO: this assumes input file is always "input"
        const self: *FileDescriptionStdin = @fieldParentPtr("desc", desc);
        if (!self.input_opened) {
            if (fs.file_manager.fileContent("input")) |content| {
                self.desc.buf = content;
                self.input_opened = true;
            } else {
                log.warn("tried to read from stdin, but there's no file named 'input'\n", .{});
                return @as(usize, 0);
            }
        }

        // We already have a buf, so just read from it as if it were a regular file
        return FileDescriptionRegular.read(&self.desc, buf);
    }

    fn write(desc: *FileDescription, buf: UserSlice([]const u8)) mem.safe.Error!usize {
        _ = desc;
        log.warn("writing to stdin, maybe a bug?\n", .{});
        return printUserMaybe(buf);
    }
};

pub const FileDescriptionStdout = struct {
    desc: FileDescription,

    pub fn create(allocator: Allocator) Allocator.Error!*FileDescriptionStdout {
        // Same as with FileDescriptionStdin.
        const ret = try allocator.create(FileDescriptionStdout);
        ret.* = FileDescriptionStdout{
            .desc = FileDescription{
                .buf = &[_]u8{},
                .flags = .{ .ACCMODE = .RDWR },
                .statFn = stat,
                .readFn = read,
                .writeFn = write,
                .ref = FileDescription.RefCounter.init(allocator, null),
            },
        };
        return ret;
    }

    fn stat(desc: *FileDescription, stat_ptr: UserPtr(*linux.Stat)) mem.safe.Error!void {
        _ = desc;
        return statStdout(stat_ptr);
    }

    fn read(desc: *FileDescription, buf: UserSlice([]u8)) mem.safe.Error!usize {
        _ = desc;
        _ = buf;
        unreachable;
    }

    fn write(desc: *FileDescription, buf: UserSlice([]const u8)) mem.safe.Error!usize {
        _ = desc;
        return printUserMaybe(buf);
    }
};

pub const FileDescriptionStderr = FileDescriptionStdout;

fn printUserMaybe(buf: UserSlice([]const u8)) mem.safe.Error!usize {
    if (build_options.enable_guest_output) {
        mem.safe.printUser(buf) catch |err| switch (err) {
            error.OutOfMemory => log.warn("printUser OOM, ignoring\n", .{}),
            error.Fault => return error.Fault,
        };
    }

    return buf.len();
}

pub const FileDescriptionSocket = struct {
    desc: FileDescription,
    socket_type: SocketType,
    bound: bool,
    listening: bool,
    connected: bool,

    pub const SocketType = struct {
        domain: i32,
        type_: i32,
        protocol: i32,
    };

    pub fn create(
        allocator: Allocator,
        buf: []const u8,
        socket_type: SocketType,
    ) Allocator.Error!*FileDescriptionSocket {
        const ret = try allocator.create(FileDescriptionSocket);
        ret.* = FileDescriptionSocket{
            .desc = FileDescription{
                .buf = buf,
                .flags = .{ .ACCMODE = .RDWR },
                .statFn = stat,
                .readFn = read,
                .writeFn = write,
                .ref = FileDescription.RefCounter.init(allocator, destroy),
                .is_socket = true,
            },
            .socket_type = socket_type,
            .bound = false,
            .listening = false,
            .connected = false,
        };
        return ret;
    }

    fn destroy(desc: *FileDescription) void {
        const self: *FileDescriptionSocket = @fieldParentPtr("desc", desc);
        self.desc.ref.allocator.destroy(self);
    }

    fn stat(desc: *FileDescription, stat_ptr: UserPtr(*linux.Stat)) !void {
        _ = desc;
        _ = stat_ptr;
        TODO();
    }

    fn read(desc: *FileDescription, buf: UserSlice([]u8)) !usize {
        // Check we're connected, and read as a regular file.
        const self: *FileDescriptionSocket = @fieldParentPtr("desc", desc);
        if (!self.connected)
            return error.NotConnected;
        return FileDescriptionRegular.read(&self.desc, buf);
    }

    fn write(desc: *FileDescription, buf: UserSlice([]const u8)) !usize {
        _ = desc;
        _ = buf;
        TODO();
    }

    pub fn bind(
        self: *FileDescriptionSocket,
        addr_ptr: UserPtr(*const linux.sockaddr),
        addr_len: usize,
    ) void {
        _ = addr_ptr;
        _ = addr_len;
        self.bound = true;
    }

    pub fn listen(self: *FileDescriptionSocket, backlock: i32) void {
        // In case it is not bound, we must assign the address and the port
        _ = backlock;
        assert(self.bound);
        self.listening = true;
    }
};
