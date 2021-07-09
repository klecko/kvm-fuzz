usingnamespace @import("../common.zig");
const mem = @import("../mem/mem.zig");
const UserPtr = mem.safe.UserPtr;
const UserSlice = mem.safe.UserSlice;
const linux = @import("../linux.zig");

pub fn statRegular(stat_ptr: UserPtr(*linux.stat), fileSize: usize, inode: linux.ino_t) isize {
    // This structure is built at compile time, so the code generated for this
    // function is just a memcpy, some writes for the undefined values that
    // differ for each file, and a call to copyToUserSingle.
    // zig fmt: off
    comptime const regular_st_base = linux.stat{
        .dev         = 2052,
        .ino         = undefined,
        .nlink       = 1,
        .mode        = 0o100664,
        .uid         = 0,
        .gid         = 0,
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
    };
    // zig fmt: on

    var st = regular_st_base;
    st.ino = inode;
    st.size = @intCast(i64, fileSize);
    st.blocks = @intCast(i64, fileSize / 512 + 1);
    mem.safe.copyToUserSingle(linux.stat, stat_ptr, &st) catch return -linux.EFAULT;
    return 0;
}

pub fn statStdin(stat_ptr: UserPtr(*linux.stat)) isize {
    // Here it's just the call to copyToUserSingle.
    // zig fmt: off
    comptime const stdin_stat = linux.stat{
        .dev         = 24,
        .ino         = 15,
        .nlink       = 1,
        .mode        = 0o20620,
        .uid         = 0,
        .gid         = 0,
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
    };
    // zig fmt: on

    mem.safe.copyToUserSingle(linux.stat, stat_ptr, &stdin_stat) catch return -linux.EFAULT;
    return 0;
}

pub fn statStdout(stat_ptr: UserPtr(*linux.stat)) isize {
    // zig fmt: off
    comptime const stdout_stat = linux.stat{
        .dev         = 22,
        .ino         = 6,
        .nlink       = 1,
        .mode        = 0o20620,
        .uid         = 0,
        .gid         = 0,
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
    };
    // zig fmt: on

    mem.safe.copyToUserSingle(linux.stat, stat_ptr, &stdout_stat) catch return -linux.EFAULT;
    return 0;
}

pub const FileDescription = struct {
    /// Pointer to file content
    buf: []const u8,

    /// Flags specified when calling open (O_RDONLY, O_RDWR...)
    flags: u32,

    /// Cursor offset
    offset: usize = 0,

    // File operations
    stat: fn (self: *FileDescription, stat_ptr: UserPtr(*linux.stat)) isize,
    read: fn (self: *FileDescription, buf: UserSlice([]u8)) isize,
    write: fn (self: *FileDescription, buf: UserSlice([]const u8)) isize,

    const O_ACCMODE = 3;

    pub fn isReadable(self: *const FileDescription) bool {
        const access_mode = self.flags & O_ACCMODE;
        return (access_mode == linux.O_RDONLY) or (access_mode == linux.O_RDWR);
    }

    pub fn isWritable(self: *const FileDescription) bool {
        const access_mode = self.flags & O_ACCMODE;
        return (access_mode == linux.O_WRONLY) or (access_mode == linux.O_RDWR);
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
};

pub const FileDescriptionRegular = struct {
    desc: FileDescription,

    pub fn init(buf: []const u8, flags: u32) FileDescriptionRegular {
        return FileDescriptionRegular{
            .desc = FileDescription{
                .buf = buf,
                .flags = flags,
                .stat = stat,
                .read = read,
                .write = write,
            },
        };
    }

    fn stat(desc: *FileDescription, stat_ptr: UserPtr(*linux.stat)) isize {
        // Use the pointer to the buffer as inode, as that's unique for each file.
        return statRegular(stat_ptr, desc.size, @ptrToInt(desc.buf.ptr));
    }

    fn read(desc: *FileDescription, buf: UserSlice([]u8)) isize {
        assert(desc.isReadable());

        // We must take of this here, as slicing OOB is UB even when the length is 0.
        if (desc.isOffsetPastEnd())
            return 0;

        const prev_offset = desc.offset;
        const length_moved = desc.moveOffset(buf.len());
        const src_slice = desc.buf[prev_offset .. prev_offset + length_moved];
        mem.safe.copyToUser(u8, buf, src_slice) catch return -EFAULT;
        return length_moved;
    }

    fn write(desc: *FileDescription, buf: UserSlice([]const u8)) isize {
        unreachable;
    }
};

pub const FileDescriptionStdin = struct {
    desc: FileDescription,
    input_opened: bool,

    pub fn init() FileDescriptionRegular {
        return FileDescriptionRegular{
            .desc = FileDescription{
                .buf = {},
                .flags = linux.O_RDWR,
                .stat = stat,
                .read = read,
                .write = write,
            },
            .input_opened = true,
        };
    }

    fn stat(desc: *FileDescription, stat_ptr: UserPtr(*linux.stat)) isize {
        return statStdin(stat_ptr);
    }

    fn read(desc: *FileDescription, buf: UserSlice([]u8)) isize {
        // Guest is trying to read from stdin. Let's do a little hack here.
        // Assuming it's expecting to read from input file, let's set that input
        // file as our buffer, and read from there as a regular file.
        // We can't do this at the beginning, as we wouldn't get the real size from
        // the hypervisor when it updated the input file.
        const self = @fieldParentPtr(FileDescriptionStdin, "desc", desc);
        if (!self.input_opened) {
            self.input_opened = true;
        }
        // TODO
    }

    fn write(desc: *FileDescription, buf: UserSlice([]const u8)) isize {
        // TODO
    }
};

pub const FileDescriptionStdout = struct {};
