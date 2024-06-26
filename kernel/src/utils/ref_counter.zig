const std = @import("std");

// Problem of this approach: in the file descriptor table we want pointers to
// FileDescription's, but these pointer actually point to FileDescription's inside
// the child classes (FileDescriptionStdin, etc), so we need to allocate and free
// the whole object of the child class, and not just the FileDescription.
// pub fn RefCounted(comptime T: type) type {
//     return struct {
//         value: T,
//         ref_count: usize,
//         allocator: *std.mem.Allocator,

//         const Self = @This();

//         pub fn create(allocator: *std.mem.Allocator, value: T) !*Self {
//             const ret = try allocator.create(Self);
//             ret.* = Self{
//                 .value = value,
//                 .ref_count = 1,
//                 .allocator = allocator,
//             };
//             return ret;
//         }

//         pub fn unref(self: *Self) void {
//             self.ref_count -= 1;
//             if (self.ref_count == 0) {
//                 self.allocator.destroy(self);
//             }
//         }
//     };
// }

/// Reference counter. ParentT is the type of the object that holds the
/// reference counter. This needn't to be the ref-counted object. We may have
/// an object A with a field B which has a field RefCounter(B), but A is the
/// object we want to count references of. In that case, A must define a destroy
/// method which will receive a pointer to B (ParentT), and which should use
/// @fieldParentPtr to get its pointer and free it.
/// If ParentT is the type of the ref-counted object, the destroy function is
/// also useful if the object requires to free other resources before freeing
/// itself. If that's not the case, there's no need to provide a destroy
/// function: the RefCounter will free the parent object itself.
pub fn RefCounter(comptime RefCountT: type, comptime ParentT: type) type {
    if (@typeInfo(RefCountT) != .Int) {
        @compileError("RefCountT should be an integer type, but found " ++ RefCountT);
    }
    return struct {
        ref_count: RefCountT,
        allocator: std.mem.Allocator,
        destroyFn: ?DestroyFn,

        const Self = @This();
        const DestroyFn = *const fn (parent: *ParentT) void;

        /// The name of the field that holds us in ParentT.
        const field_name = blk: {
            var name: []const u8 = undefined;
            var found: bool = false;
            for (@typeInfo(ParentT).Struct.fields) |field| {
                if (field.type == Self) {
                    if (found == false) {
                        name = field.name;
                        found = true;
                    } else {
                        @compileError("ParentT has more than one field of type RefCounter(ParentT)");
                    }
                }
            }
            if (!found)
                @compileError("ParentT doens't have any field of type RefCounter(ParentT)");
            break :blk name;
        };

        /// Initialize the reference counter. `allocator` is the allocator that
        /// will free the ref-counted object, and `destroyFn` is the function in
        /// charge of doing that. If the ref-counted object is the one of type
        /// ParentT that holds us and it is only needed to free the object,
        /// then there's no need to provide a destroy function. If that's not
        /// the case (e.g. the ref-counted object is the parent of the object
        /// that holds us, as in FileDescription; or more resources need to be
        /// freed before freeing the object, as in FileDescriptionTable), then
        /// `destroyFn` must be provided.
        pub fn init(allocator: std.mem.Allocator, destroyFn: ?DestroyFn) Self {
            return Self{
                .ref_count = 1,
                .allocator = allocator,
                .destroyFn = destroyFn,
            };
        }

        /// Increment the reference counter and return a pointer to the parent.
        pub fn ref(self: *Self) *ParentT {
            self.ref_count += 1;
            return @fieldParentPtr(field_name, self);
        }

        /// Decrement the reference counter, freeing the ref-counted object if
        /// it reached 0.
        pub fn unref(self: *Self) void {
            std.debug.assert(self.ref_count > 0);
            self.ref_count -= 1;
            if (self.ref_count == 0) {
                const parent: *ParentT = @fieldParentPtr(field_name, self);
                if (self.destroyFn) |destroy| {
                    destroy(parent);
                } else {
                    self.allocator.destroy(parent);
                }
            }
        }
    };
}
