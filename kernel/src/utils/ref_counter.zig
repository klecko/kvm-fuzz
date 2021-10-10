usingnamespace @import("../common.zig");

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
/// method which will receive a pointer to the RefCounter, and which should use
/// @fieldParentPtr to get its pointer and free it.
/// If ParentT is the type of the ref-counted object, then there's no need to
/// provide a destroy function. The RefCounter will free the parent object itself.
pub fn RefCounter(comptime ParentT: type) type {
    return struct {
        ref_count: usize,
        allocator: *std.mem.Allocator,
        destroyFn: ?(fn (self: *Self) void),

        const Self = @This();
        const field_name = getParentFieldName();

        /// Gets the name of the field that holds us in ParentT.
        fn getParentFieldName() []const u8 {
            comptime {
                var name: []const u8 = undefined;
                var found: bool = false;
                for (@typeInfo(ParentT).Struct.fields) |field| {
                    if (field.field_type == Self) {
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
                return name;
            }
        }

        /// Initialize the reference counter. `allocator` is the allocator that
        /// will free the ref-counted object, and `destroyFn` is the function in
        /// charge of doing that. If the ref-counted object is the one of type
        /// ParentT that holds us, then there's no need to provide a destroy
        /// function. If it isn't (e.g. it's an object that holds our parent),
        /// then it must be provided. An example of this can be seen in
        /// FileDescription.
        pub fn init(allocator: *std.mem.Allocator, destroyFn: ?(fn (self: *Self) void)) Self {
            return Self{
                .ref_count = 1,
                .allocator = allocator,
                .destroyFn = destroyFn,
            };
        }

        /// Increment the reference counter and return a pointer to the parent.
        pub fn ref(self: *Self) *ParentT {
            self.ref_count += 1;
            return @fieldParentPtr(ParentT, field_name, self);
        }

        /// Decrement the reference counter, freeing the ref-counted object if
        /// it reached 0.
        pub fn unref(self: *Self) void {
            self.ref_count -= 1;
            if (self.ref_count == 0) {
                if (self.destroyFn) |destroy| {
                    destroy(self);
                } else {
                    self.allocator.destroy(@fieldParentPtr(ParentT, field_name, self));
                }
            }
        }
    };
}
