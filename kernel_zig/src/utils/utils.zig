usingnamespace @import("../common.zig");
pub const RefCounter = @import("ref_counter.zig").RefCounter;

/// Convert a slice type to a u8 pointer of size ptr_size, conserving every other attribute
fn BytePtrType(comptime ptr_size: std.builtin.TypeInfo.Pointer.Size, comptime slice_type: type) type {
    comptime {
        var type_info = @typeInfo(slice_type);
        if (type_info != .Pointer or type_info.Pointer.size != .Slice) {
            @compileLog(T, @typeInfo(T).Pointer.size);
            @compileError("a slice is required >:(");
        }
        type_info.Pointer.child = u8;
        type_info.Pointer.size = ptr_size;
        return @Type(type_info);
    }
}

/// Convert an arbitrary slice to a slice of bytes. For single items, use
/// std.mem.asBytes.
pub fn sliceToBytes(slice: anytype) BytePtrType(.Slice, @TypeOf(slice)) {
    const T = @TypeOf(slice);
    return @ptrCast(BytePtrType(.Many, T), slice.ptr)[0 .. slice.len * @sizeOf(T)];
}
