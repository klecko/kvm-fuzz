usingnamespace @import("../common.zig");
const interrupts = @import("../interrupts.zig");

// TODO: check given pointers are actually in userspace

/// A wrapper for userspace pointers. T is the type of the pointer, e.g. *u8.
pub fn UserPtr(comptime T: type) type {
    assert(@typeInfo(T) == .Pointer);
    if (@typeInfo(T).Pointer.size == .Slice)
        @compileError("Use UserSlice(T) for slices");

    return struct {
        _ptr: T,

        const Self = @This();
        const ConstT = blk: {
            comptime var typeInfo = @typeInfo(T);
            typeInfo.Pointer.is_const = true;
            break :blk @Type(typeInfo);
        };

        /// Create a UserPtr from a regular pointer.
        pub fn fromPtr(user_ptr: T) Self {
            return Self{
                ._ptr = user_ptr,
            };
        }

        /// Create a UserPtr from an integer.
        pub fn fromFlat(user_ptr: usize) Self {
            return Self{
                ._ptr = @intToPtr(T, user_ptr),
            };
        }

        /// Get the raw pointer.
        pub fn ptr(self: Self) T {
            return self._ptr;
        }

        /// Get the pointer as usize.
        pub fn flat(self: Self) usize {
            return @ptrToInt(self._ptr);
        }

        /// Get the const version of the UserPtr.
        pub fn toConst(self: Self) UserPtr(ConstT) {
            return UserPtr(ConstT).fromPtr(self._ptr);
        }
    };
}

/// A wrapper for userspace slices. T is the type of the slice, e.g. []u8.
pub fn UserSlice(comptime T: type) type {
    assert(@typeInfo(T) == .Pointer);
    assert(@typeInfo(T).Pointer.size == .Slice);
    return struct {
        _slice: T,

        const Self = @This();
        const ConstT = blk: {
            comptime var typeInfo = @typeInfo(T);
            typeInfo.Pointer.is_const = true;
            break :blk @Type(typeInfo);
        };

        /// Create a UserSlice from a regular slice.
        pub fn fromSlice(user_slice: T) Self {
            return Self{
                ._slice = user_slice,
            };
        }

        /// Create a UserSlice from a pointer as integer and a length.
        pub fn fromFlat(user_ptr: usize, length: usize) Self {
            const PointerT = blk: {
                comptime var typeInfo = @typeInfo(T);
                typeInfo.Pointer.size = .Many;
                break :blk @Type(typeInfo);
            };
            const slice = @intToPtr(PointerT, user_ptr)[0..length];
            return fromSlice(slice);
        }

        /// Get the length of the slice.
        pub fn len(self: Self) usize {
            return self._slice.len;
        }

        /// Get the raw slice.
        pub fn slice(self: Self) T {
            return self._slice;
        }

        /// Get the const version of the UserSlice.
        pub fn toConst(self: Self) UserSlice(ConstT) {
            comptime assert(T != ConstT);
            return UserSlice(ConstT).fromSlice(self._slice);
        }
    };
}

comptime {
    assert(@sizeOf(UserPtr(*u8)) == @sizeOf(*u8));
    assert(@sizeOf(UserSlice([]u8)) == @sizeOf([]u8));
}

// TODO: check user ranges

pub fn copyToUser(comptime T: type, dest: UserSlice([]T), src: []const T) bool {
    return copy(T, dest.slice(), src);
}

pub fn copyToUserSingle(comptime T: type, dest: UserPtr(*T), src: *const T) bool {
    return copySingle(T, dest.ptr(), src);
}

pub fn copyFromUser(comptime T: type, dest: []T, src: UserSlice([]const T)) bool {
    return copy(T, dest, src.slice());
}

pub fn copyFromUserSingle(comptime T: type, dest: *T, src: UserPtr(*const T)) bool {
    return copy(T, dest, src.ptr());
}

fn copy(comptime T: type, dest: []T, src: []const T) bool {
    assert(dest.len >= src.len);
    const dest_len = dest.len * @sizeOf(T);
    const src_len = src.len * @sizeOf(T);
    const dest_u8 = @ptrCast([*]u8, dest.ptr)[0..dest_len];
    const src_u8 = @ptrCast([*]const u8, src.ptr)[0..src_len];
    return copyBase(dest_u8, src_u8);
}

fn copySingle(comptime T: type, dest: *T, src: *const T) bool {
    const dest_u8 = @ptrCast([*]u8, dest)[0..@sizeOf(T)];
    const src_u8 = @ptrCast([*]const u8, src)[0..@sizeOf(T)];
    return copyBase(dest_u8, src_u8);
}

extern const safe_copy_ins_may_fault: usize;
extern const safe_copy_ins_faulted: usize;

pub fn handleSafeAccessFault(frame: *interrupts.InterruptFrame) bool {
    if (frame.rip == @ptrToInt(&safe_copy_ins_may_fault)) {
        frame.rip = @ptrToInt(&safe_copy_ins_faulted);
    } else return false;
    return true;
}

noinline fn copyBase(dest: []u8, src: []const u8) bool {
    const bytes_left = asm volatile (
        \\safe_copy_ins_may_fault:
        \\rep movsb
        \\safe_copy_ins_faulted:
        : [ret] "={rcx}" (-> usize)
        : [dest] "{rdi}" (dest.ptr),
          [src] "{rsi}" (src.ptr),
          [len] "{rcx}" (src.len)
    );
    return bytes_left == 0;
}

noinline fn endCopyBase() void {}
