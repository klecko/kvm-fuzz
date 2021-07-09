usingnamespace @import("../common.zig");
const interrupts = @import("../interrupts.zig");
const mem = @import("mem.zig");

pub fn isAddressInUserRange(addr: usize) bool {
    return addr < mem.layout.user_end;
}

pub fn isRangeInUserRange(addr: usize, len: usize) bool {
    return if (std.math.add(usize, addr, len)) |addr_end|
        isAddressInUserRange(addr) and isAddressInUserRange(addr_end - 1)
    else |err|
        false; // Overflow occurred
}

pub fn isPtrInUserRange(comptime T: type, ptr: *const T) bool {
    return isAddressInUserRange(@ptrToInt(ptr));
}

pub fn isSliceInUserRange(comptime T: type, slice: []const T) bool {
    return isRangeInUserRange(@ptrToInt(slice.ptr), slice.len * @sizeOf(T));
}

pub fn isAddressInKernelRange(addr: usize) bool {
    return addr >= mem.layout.kernel_start;
}

pub fn isRangeInKernelRange(addr: usize, len: usize) bool {
    return if (std.math.add(usize, addr, len)) |addr_end|
        isAddressInKernelRange(addr) and isAddressInKernelRange(addr_end - 1)
    else |err|
        false; // Overflow occurred
}

pub fn isPtrInKernelRange(comptime T: type, ptr: *const T) bool {
    return isAddressInKernelRange(@ptrToInt(ptr));
}

pub fn isSliceInKernelRange(comptime T: type, slice: []const T) bool {
    return isRangeInKernelRange(@ptrToInt(slice.ptr), slice.len * @sizeOf(T));
}

/// A wrapper for pointers given from userspace. T is the type of the pointer, e.g. *u8.
/// Note this doesn't mean the underlying pointer belongs to user range: it could
/// belong to kernel range or be an invalid address.
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
/// Note this doesn't mean the underlying range belongs to user range: it could
/// belong to kernel range or be an invalid range.
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

// The following functions should be used for copying from UserSlice and UserPtr
// to kernel memory. They return an error if the copy was not successful.
// In order to do so, first they check memory is in correct ranges. If the given
// kernel pointer or slice is not in kernel range, that's a bug. If the given user
// pointer or slice is not in user range, they will return Error.NotUserRange.
// If both are correct, then they try to perform the copy. If a fault occurs then,
// they will return Error.Fault. This can happen because memory is not mapped,
// or mapped without write permissiong.

pub const Error = error{ NotUserRange, Fault };

pub fn copyToUser(comptime T: type, dest: UserSlice([]T), src: []const T) Error!void {
    // Make sure we're copying from kernel to user.
    assert(isSliceInKernelRange(T, src));
    if (!isSliceInUserRange(T, dest.slice()))
        return Error.NotUserRange;

    // Try to perform copy.
    try copy(T, dest.slice(), src);
}

pub fn copyToUserSingle(comptime T: type, dest: UserPtr(*T), src: *const T) Error!void {
    // Make sure we're copying from kernel to user.
    assert(isPtrInKernelRange(T, src));
    if (!isPtrInUserRange(T, dest.ptr()))
        return Error.NotUserRange;

    // Try to perform copy.
    try copySingle(T, dest.ptr(), src);
}

pub fn copyFromUser(comptime T: type, dest: []T, src: UserSlice([]const T)) Error!void {
    // Make sure we're copying from user to kernel.
    assert(isSliceInKernelRange(T, dest));
    if (!isSliceInUserRange(T, src.slice()))
        return Error.NotUserRange;

    // Try to perform copy.
    try copy(T, dest, src.slice());
}

pub fn copyFromUserSingle(comptime T: type, dest: *T, src: UserPtr(*const T)) Error!void {
    // Make sure we're copying from user to kernel.
    assert(isPtrInKernelRange(T, dest));
    if (!isPtrInUserRange(T, src.slice()))
        return Error.NotUserRange;

    // Try to perform copy.
    try copy(T, dest, src.ptr());
}

// The following functions perform copies, and return an Error if a fault
// occurred.
fn copy(comptime T: type, dest: []T, src: []const T) Error!void {
    assert(dest.len >= src.len);
    const dest_len = dest.len * @sizeOf(T);
    const src_len = src.len * @sizeOf(T);
    const dest_u8 = @ptrCast([*]u8, dest.ptr)[0..dest_len];
    const src_u8 = @ptrCast([*]const u8, src.ptr)[0..src_len];
    try copyBase(dest_u8, src_u8);
}

fn copySingle(comptime T: type, dest: *T, src: *const T) Error!void {
    const dest_u8 = @ptrCast([*]u8, dest)[0..@sizeOf(T)];
    const src_u8 = @ptrCast([*]const u8, src)[0..@sizeOf(T)];
    try copyBase(dest_u8, src_u8);
}

extern const safe_copy_ins_may_fault: usize;
extern const safe_copy_ins_faulted: usize;

pub fn handleSafeAccessFault(frame: *interrupts.InterruptFrame) bool {
    if (frame.rip == @ptrToInt(&safe_copy_ins_may_fault)) {
        frame.rip = @ptrToInt(&safe_copy_ins_faulted);
    } else return false;
    return true;
}

noinline fn copyBase(dest: []u8, src: []const u8) Error!void {
    const bytes_left = asm volatile (
        \\safe_copy_ins_may_fault:
        \\rep movsb
        \\safe_copy_ins_faulted:
        : [ret] "={rcx}" (-> usize)
        : [dest] "{rdi}" (dest.ptr),
          [src] "{rsi}" (src.ptr),
          [len] "{rcx}" (src.len)
    );
    if (bytes_left != 0)
        return Error.Fault;
}

// This is needed for the label symbols to be generated if `copyBase`
// is not called
comptime {
    _ = copyBase;
}
