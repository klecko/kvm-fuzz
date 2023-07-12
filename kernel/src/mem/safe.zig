const common = @import("../common.zig");
const print = common.print;
const std = @import("std");
const assert = std.debug.assert;
const interrupts = @import("../interrupts.zig");
const mem = @import("mem.zig");
const utils = @import("../utils/utils.zig");
const Allocator = std.mem.Allocator;

pub fn isAddressInUserRange(addr: usize) bool {
    return addr < mem.layout.user_end;
}

pub fn isRangeInUserRange(addr: usize, len: usize) bool {
    // We allow empty ranges here so copyFromUser and copyToUser don't fail
    // with empty slices pointing to wrong region.
    const addr_end = std.math.add(usize, addr, len) catch return false;
    return len == 0 or (isAddressInUserRange(addr) and isAddressInUserRange(addr_end - 1));
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
    const addr_end = std.math.add(usize, addr, len) catch return false;
    return len == 0 or (isAddressInKernelRange(addr) and isAddressInKernelRange(addr_end - 1));
}

pub fn isPtrInKernelRange(comptime T: type, ptr: *const T) bool {
    return isAddressInKernelRange(@ptrToInt(ptr));
}

pub fn isSliceInKernelRange(comptime T: type, slice: []const T) bool {
    return isRangeInKernelRange(@ptrToInt(slice.ptr), slice.len * @sizeOf(T));
}

/// A wrapper for userspace pointers. T is the type of the pointer, e.g. *u8.
/// This checks the underlying pointer belongs to user range, but it could still
/// be an invalid address (not mapped or mapped with wrong permissions).
/// TODO: unaligned pointers crash
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
        const ChildT = @typeInfo(T).Pointer.child;

        /// Create a UserPtr from a regular pointer.
        pub fn fromPtr(user_ptr: T) !Self {
            return if (!isPtrInUserRange(ChildT, user_ptr))
                error.NotUserRange
            else
                Self{
                    ._ptr = user_ptr,
                };
        }

        /// Create a UserPtr from an integer.
        pub fn fromFlat(user_ptr: usize) !Self {
            return if (user_ptr == 0 or !isAddressInUserRange(user_ptr))
                error.NotUserRange
            else
                Self{
                    ._ptr = @intToPtr(T, user_ptr),
                };
        }

        pub fn fromFlatMaybeNull(user_ptr: usize) !?Self {
            return if (user_ptr == 0)
                null
            else if (!isAddressInUserRange(user_ptr))
                error.NotUserRange
            else
                Self{
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
            return UserPtr(ConstT).fromPtr(self._ptr) catch unreachable;
        }
    };
}

/// A wrapper for userspace slices. T is the type of the slice, e.g. []u8.
/// This checks the underlying pointer belongs to user range, but it could still
/// be an invalid address (not mapped or mapped with wrong permissions).
/// TODO: unaligned pointers crash
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
        const ChildT = @typeInfo(T).Pointer.child;

        /// Create a UserSlice from a regular slice.
        pub fn fromSlice(user_slice: T) !Self {
            return if (!isSliceInUserRange(ChildT, user_slice))
                error.NotUserRange
            else
                Self{
                    ._slice = user_slice,
                };
        }

        /// Create a UserSlice from a pointer as integer and a length.
        pub fn fromFlat(user_ptr: usize, length: usize) !Self {
            if (user_ptr == 0)
                return error.NotUserRange;
            const PointerT = blk: {
                comptime var type_info = @typeInfo(T);
                type_info.Pointer.size = .Many;
                break :blk @Type(type_info);
            };
            const user_slice = @intToPtr(PointerT, user_ptr)[0..length];
            return fromSlice(user_slice);
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
            return UserSlice(ConstT).fromSlice(self._slice) catch unreachable;
        }

        const PtrAtPointerType = blk: {
            comptime var type_info = @typeInfo(T);
            type_info.Pointer.size = .One;
            break :blk @Type(type_info);
        };

        pub fn ptrAt(self: Self, idx: usize) UserPtr(PtrAtPointerType) {
            assert(idx < self.len());
            const ptr = @ptrCast(PtrAtPointerType, self.slice().ptr + idx);
            return UserPtr(PtrAtPointerType).fromPtr(ptr) catch unreachable;
        }

        pub fn sliceTo(self: Self, new_len: usize) Self {
            assert(new_len <= self.len());
            return Self.fromSlice(self.slice()[0..new_len]) catch unreachable;
        }
    };
}

comptime {
    assert(@sizeOf(UserPtr(*u8)) == @sizeOf(*u8));
    assert(@sizeOf(UserSlice([]u8)) == @sizeOf([]u8));
}

// The following functions should be used for copying from UserSlice and UserPtr
// to kernel memory and viceversa. They return error.Fault if a fault occurred
// when performing the copy. This can happen because memory is not mapped, or it
// is mapped with wrong permissions.

pub const UserCString = UserPtr([*:0]const u8);

pub const Error = error{Fault};

pub fn copyToUser(comptime T: type, dest: UserSlice([]T), src: []const T) Error!void {
    // Make sure we're copying from kernel to user.
    assert(isSliceInKernelRange(T, src));
    assert(isSliceInUserRange(T, dest.slice()));

    // Try to perform copy.
    try copy(T, dest.slice(), src);
}

pub fn copyToUserSingle(comptime T: type, dest: UserPtr(*T), src: *const T) Error!void {
    // Make sure we're copying from kernel to user.
    assert(isPtrInKernelRange(T, src));
    assert(isPtrInUserRange(T, dest.ptr()));

    // Try to perform copy.
    try copySingle(T, dest.ptr(), src);
}

pub fn copyFromUser(comptime T: type, dest: []T, src: UserSlice([]const T)) Error!void {
    // Make sure we're copying from user to kernel.
    assert(isSliceInKernelRange(T, dest));
    assert(isSliceInUserRange(T, src.slice()));

    // Try to perform copy.
    try copy(T, dest, src.slice());
}

pub fn copyFromUserSingle(comptime T: type, src: UserPtr(*const T)) Error!T {
    // Make sure we're copying from user.
    assert(isPtrInUserRange(T, src.ptr()));

    // Try to perform copy.
    var ret: T = undefined;
    try copySingle(T, &ret, src.ptr());
    return ret;
}

pub fn copyStringFromUser(allocator: Allocator, string_ptr: UserCString) (Allocator.Error || Error)![]u8 {
    const length = try strlen(string_ptr.ptr());
    var string = try allocator.alloc(u8, length);
    errdefer allocator.free(string);
    const user_string_slice = UserSlice([]const u8).fromFlat(string_ptr.flat(), length) catch unreachable;
    try copyFromUser(u8, string, user_string_slice);
    return string;
}

pub fn printUser(user_buf: UserSlice([]const u8)) (Error || std.mem.Allocator.Error)!void {
    // Allocate a temporary buffer
    var tmp_buf = try mem.heap.page_allocator.alloc(u8, user_buf.len());
    defer mem.heap.page_allocator.free(tmp_buf);

    // Copy string from user buffer and print it
    try copyFromUser(u8, tmp_buf, user_buf);
    print("{s}", .{tmp_buf});
}

// The following functions perform copies, and return an Error if a fault
// occurred.
fn copy(comptime T: type, dest: []T, src: []const T) Error!void {
    assert(dest.len == src.len);
    try copyBase(std.mem.sliceAsBytes(dest), std.mem.sliceAsBytes(src));
}

fn copySingle(comptime T: type, dest: *T, src: *const T) Error!void {
    try copyBase(std.mem.asBytes(dest), std.mem.asBytes(src));
}

// Low level implementation
extern const safe_copy_ins_may_fault: usize;
extern const safe_copy_ins_faulted: usize;
extern const safe_strlen_ins_may_fault: usize;
extern const safe_strlen_ins_faulted: usize;

pub fn handleSafeAccessFault(frame: *interrupts.InterruptFrame) bool {
    if (frame.rip == @ptrToInt(&safe_copy_ins_may_fault)) {
        frame.rip = @ptrToInt(&safe_copy_ins_faulted);
    } else if (frame.rip == @ptrToInt(&safe_strlen_ins_may_fault)) {
        frame.rip = @ptrToInt(&safe_strlen_ins_faulted);
    } else return false;
    return true;
}

noinline fn copyBase(dest: []u8, src: []const u8) Error!void {
    const bytes_left = asm volatile (
        \\safe_copy_ins_may_fault:
        \\rep movsb
        \\safe_copy_ins_faulted:
        : [ret] "={rcx}" (-> usize),
        : [dest] "{rdi}" (dest.ptr),
          [src] "{rsi}" (src.ptr),
          [len] "{rcx}" (src.len),
    );
    if (bytes_left != 0)
        return Error.Fault;
}

noinline fn strlen(s: [*:0]const u8) Error!usize {
    var fault: bool = undefined;
    const result = asm volatile (
    // Look for null byte
        \\xor %%rax, %%rax

        // Set rcx to -1 so we scan until we find a null byte
        \\xor %%rcx, %%rcx
        \\dec %%rcx

        // Perform scan, setting rcx to the string length and fault to false
        \\safe_strlen_ins_may_fault:
        \\repne scasb
        \\not %%rcx
        \\dec %%rcx
        \\mov $0, %[fault]
        \\jmp end

        // If we faulted, set fault to true
        \\safe_strlen_ins_faulted:
        \\mov $1, %[fault]
        \\end:
        : [len] "={rcx}" (-> usize),
          [fault] "=r" (fault),
        : [s] "{rdi}" (s),
        : "rax", "rcx", "rdi"
    );
    return if (fault) Error.Fault else result;
}

// This is needed for the label symbols to be generated if these functions
// are not called
comptime {
    _ = copyBase;
    _ = strlen;
}
