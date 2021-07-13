usingnamespace @import("../common.zig");
const mem = @import("mem.zig");
const log = std.log.scoped(.heap);
const math = std.math;
const page_size = std.mem.page_size;
const StackTrace = std.builtin.StackTrace;
const Allocator = std.mem.Allocator;

/// The kernel page allocator. It is just a wrapper around the VMM, allocating
/// kernel writable pages. Because of that, it won't work until the VMM is
/// initialized.
var page_allocator_state = PageAllocator.init();
pub const page_allocator = &page_allocator_state.allocator;

var heap_allocator_state = mem.heap.HeapAllocator.init();
pub const heap_allocator = &heap_allocator_state.allocator;

pub fn initHeapAllocator() void {
    heap_allocator_state.base = mem.layout.kernel_brk;
}

pub const HeapAllocator = struct {
    allocator: Allocator,
    base: usize,
    used: usize,
    size: usize,

    pub fn init() HeapAllocator {
        return HeapAllocator{
            .allocator = Allocator{
                .allocFn = alloc,
                .resizeFn = resize,
            },
            .base = 0,
            .used = 0,
            .size = 0,
        };
    }

    fn more(self: *HeapAllocator, num_pages: usize) Allocator.Error!void {
        const ret = try mem.vmm.allocPages(num_pages, .{
            .writable = true,
            .global = true,
            .noExecute = true,
        });
        assert(ret == self.base + self.size);
        self.size += num_pages * std.mem.page_size;
    }

    fn alloc(
        allocator: *Allocator,
        len: usize,
        ptr_align: u29,
        len_align: u29,
        ret_addr: usize,
    ) Allocator.Error![]u8 {
        const self = @fieldParentPtr(HeapAllocator, "allocator", allocator);
        const ret_offset = std.mem.alignForward(self.used, ptr_align);
        const free_bytes = self.size - ret_offset;
        if (len > free_bytes) {
            const needed_memory = mem.alignPageForward(len - free_bytes);
            const num_pages = @divExact(needed_memory, std.mem.page_size);
            try self.more(num_pages);
        }

        self.used = ret_offset + len;
        assert(self.used <= self.size);
        const ret = self.base + ret_offset;
        log.debug("heap allocator: returns 0x{x}\n", .{ret});
        return @intToPtr([*]u8, ret)[0..len];
    }

    fn resize(
        allocator: *Allocator,
        buf: []u8,
        buf_align: u29,
        new_len: usize,
        len_align: u29,
        ret_addr: usize,
    ) Allocator.Error!usize {
        if (new_len == 0) {
            log.debug("heap allocator: frees {*}\n", .{buf});
            std.mem.set(u8, buf, undefined);
            return 0;
        }
        TODO();
    }
};

const PageAllocator = struct {
    allocator: Allocator,

    pub fn init() PageAllocator {
        return PageAllocator{
            .allocator = Allocator{
                .allocFn = alloc,
                .resizeFn = resize,
            },
        };
    }

    fn alloc(allocator: *Allocator, len: usize, ptr_align: u29, len_align: u29, ret_addr: usize) Allocator.Error![]u8 {
        log.debug("page allocator alloc: {} {} {}\n", .{ len, ptr_align, len_align });

        // As we always return a page aligned pointer, with this constraint we
        // make sure it will be also aligned by ptr_align.
        assert(ptr_align <= std.mem.page_size);

        // Allocator constraints
        assert(len > 0);
        assert(std.mem.isValidAlign(ptr_align));
        if (len_align > 0) {
            assert(std.mem.isAlignedAnyAlign(len, len_align));
            assert(len >= len_align);
        }

        // The pages we're going to allocate
        const num_pages = @divExact(mem.alignPageForward(len), std.mem.page_size);

        // Alocate the pages
        const range_start = try mem.vmm.allocPages(num_pages, .{
            .writable = true,
            .global = true,
            .noExecute = true,
        });

        // Construct the slice and return it
        const range_start_ptr = @intToPtr([*]u8, range_start);
        const slice = range_start_ptr[0..len];
        log.debug("page allocator alloc return: {*}\n", .{slice.ptr});
        return slice;
    }

    fn resize(allocator: *Allocator, buf: []u8, buf_align: u29, new_len: usize, len_align: u29, ret_addr: usize) Allocator.Error!usize {
        // Same as in std.heap.PageAllocator.resize
        log.debug("page allocator resize: {*} {} {} {}\n", .{ buf, buf_align, new_len, len_align });
        assert(mem.isPageAligned(@ptrToInt(buf.ptr)));
        const new_len_aligned = mem.alignPageForward(new_len);
        const buf_len_aligned = mem.alignPageForward(buf.len);

        // No need to do anything here.
        if (new_len_aligned == buf_len_aligned)
            return std.heap.alignPageAllocLen(new_len_aligned, new_len, len_align);

        // Free pages.
        if (new_len_aligned < buf_len_aligned) {
            const base = @ptrToInt(buf.ptr) + new_len_aligned;
            const num_pages = @divExact(buf_len_aligned - new_len_aligned, std.mem.page_size);
            mem.vmm.freePages(base, num_pages) catch unreachable;
            if (new_len_aligned == 0)
                return 0;
            return std.heap.alignPageAllocLen(new_len_aligned, new_len, len_align);
        }

        // It's asking for an increase in size.
        return Allocator.Error.OutOfMemory;
    }
};

// From this point on there's the GPA code.
// This code is the same as general_purpose_allocator.zig with these changes:
//   - It doesn't print the formatted stack traces, which requires having debug
//     info and seems broken for freestanding.
//   - It uses our page_allocator as backing allocator instead of
//     std.heap.page_allocator, which defaults to root.os.heap.page_allocator.
// Every changed line is next to a '// KLECKO' comment

/// Integer type for pointing to slots in a small allocation
const SlotIndex = std.meta.Int(.unsigned, math.log2(page_size) + 1);

const sys_can_stack_trace = switch (std.Target.current.cpu.arch) {
    // Observed to go into an infinite loop.
    // TODO: Make this work.
    .mips,
    .mipsel,
    => false,

    // `@returnAddress()` in LLVM 10 gives
    // "Non-Emscripten WebAssembly hasn't implemented __builtin_return_address".
    .wasm32,
    .wasm64,
    => std.Target.current.os.tag == .emscripten,

    else => true,
};
const default_test_stack_trace_frames: usize = if (std.builtin.is_test) 8 else 4;
const default_sys_stack_trace_frames: usize = if (sys_can_stack_trace) default_test_stack_trace_frames else 0;
const default_stack_trace_frames: usize = switch (std.builtin.mode) {
    .Debug => default_sys_stack_trace_frames,
    else => 0,
};

pub const Config = struct {
    /// Number of stack frames to capture.
    stack_trace_frames: usize = default_stack_trace_frames,

    /// If true, the allocator will have two fields:
    ///  * `total_requested_bytes` which tracks the total allocated bytes of memory requested.
    ///  * `requested_memory_limit` which causes allocations to return `error.OutOfMemory`
    ///    when the `total_requested_bytes` exceeds this limit.
    /// If false, these fields will be `void`.
    enable_memory_limit: bool = false,

    /// Whether to enable safety checks.
    safety: bool = std.debug.runtime_safety,

    /// Whether the allocator may be used simultaneously from multiple threads.
    thread_safe: bool = !std.builtin.single_threaded,

    /// What type of mutex you'd like to use, for thread safety.
    /// when specfied, the mutex type must have the same shape as `std.Thread.Mutex` and
    /// `std.Thread.Mutex.Dummy`, and have no required fields. Specifying this field causes
    /// the `thread_safe` field to be ignored.
    ///
    /// when null (default):
    /// * the mutex type defaults to `std.Thread.Mutex` when thread_safe is enabled.
    /// * the mutex type defaults to `std.Thread.Mutex.Dummy` otherwise.
    MutexType: ?type = null,

    /// This is a temporary debugging trick you can use to turn segfaults into more helpful
    /// logged error messages with stack trace details. The downside is that every allocation
    /// will be leaked!
    never_unmap: bool = false,

    /// Enables emitting info messages with the size and address of every allocation.
    verbose_log: bool = false,
};

pub fn GeneralPurposeAllocator(comptime config: Config) type {
    return struct {
        allocator: Allocator = Allocator{
            .allocFn = alloc,
            .resizeFn = resize,
        },
        // KLECKO
        // backing_allocator: *Allocator = std.heap.page_allocator,
        backing_allocator: *Allocator = heap_allocator,
        // backing_allocator: *Allocator = page_allocator,
        buckets: [small_bucket_count]?*BucketHeader = [1]?*BucketHeader{null} ** small_bucket_count,
        large_allocations: LargeAllocTable = .{},

        total_requested_bytes: @TypeOf(total_requested_bytes_init) = total_requested_bytes_init,
        requested_memory_limit: @TypeOf(requested_memory_limit_init) = requested_memory_limit_init,

        mutex: @TypeOf(mutex_init) = mutex_init,

        const Self = @This();

        const total_requested_bytes_init = if (config.enable_memory_limit) @as(usize, 0) else {};
        const requested_memory_limit_init = if (config.enable_memory_limit) @as(usize, math.maxInt(usize)) else {};

        const mutex_init = if (config.MutexType) |T|
            T{}
        else if (config.thread_safe)
            std.Thread.Mutex{}
        else
            std.Thread.Mutex.Dummy{};

        const stack_n = config.stack_trace_frames;
        const one_trace_size = @sizeOf(usize) * stack_n;
        const traces_per_slot = 2;

        pub const Error = Allocator.Error;

        const small_bucket_count = math.log2(page_size);
        const largest_bucket_object_size = 1 << (small_bucket_count - 1);

        const LargeAlloc = struct {
            bytes: []u8,
            stack_addresses: [stack_n]usize,

            fn dumpStackTrace(self: *LargeAlloc) void {
                std.debug.dumpStackTrace(self.getStackTrace());
            }

            fn getStackTrace(self: *LargeAlloc) std.builtin.StackTrace {
                var len: usize = 0;
                while (len < stack_n and self.stack_addresses[len] != 0) {
                    len += 1;
                }
                return .{
                    .instruction_addresses = &self.stack_addresses,
                    .index = len,
                };
            }
        };
        const LargeAllocTable = std.AutoHashMapUnmanaged(usize, LargeAlloc);

        // Bucket: In memory, in order:
        // * BucketHeader
        // * bucket_used_bits: [N]u8, // 1 bit for every slot; 1 byte for every 8 slots
        // * stack_trace_addresses: [N]usize, // traces_per_slot for every allocation

        const BucketHeader = struct {
            prev: *BucketHeader,
            next: *BucketHeader,
            page: [*]align(page_size) u8,
            alloc_cursor: SlotIndex,
            used_count: SlotIndex,

            fn usedBits(bucket: *BucketHeader, index: usize) *u8 {
                return @intToPtr(*u8, @ptrToInt(bucket) + @sizeOf(BucketHeader) + index);
            }

            fn stackTracePtr(
                bucket: *BucketHeader,
                size_class: usize,
                slot_index: SlotIndex,
                trace_kind: TraceKind,
            ) *[stack_n]usize {
                const start_ptr = @ptrCast([*]u8, bucket) + bucketStackFramesStart(size_class);
                const addr = start_ptr + one_trace_size * traces_per_slot * slot_index +
                    @enumToInt(trace_kind) * @as(usize, one_trace_size);
                return @ptrCast(*[stack_n]usize, @alignCast(@alignOf(usize), addr));
            }

            fn captureStackTrace(
                bucket: *BucketHeader,
                ret_addr: usize,
                size_class: usize,
                slot_index: SlotIndex,
                trace_kind: TraceKind,
            ) void {
                // Initialize them to 0. When determining the count we must look
                // for non zero addresses.
                const stack_addresses = bucket.stackTracePtr(size_class, slot_index, trace_kind);
                collectStackTrace(ret_addr, stack_addresses);
            }
        };

        fn bucketStackTrace(
            bucket: *BucketHeader,
            size_class: usize,
            slot_index: SlotIndex,
            trace_kind: TraceKind,
        ) StackTrace {
            const stack_addresses = bucket.stackTracePtr(size_class, slot_index, trace_kind);
            var len: usize = 0;
            while (len < stack_n and stack_addresses[len] != 0) {
                len += 1;
            }
            return StackTrace{
                .instruction_addresses = stack_addresses,
                .index = len,
            };
        }

        fn bucketStackFramesStart(size_class: usize) usize {
            return std.mem.alignForward(
                @sizeOf(BucketHeader) + usedBitsCount(size_class),
                @alignOf(usize),
            );
        }

        fn bucketSize(size_class: usize) usize {
            const slot_count = @divExact(page_size, size_class);
            return bucketStackFramesStart(size_class) + one_trace_size * traces_per_slot * slot_count;
        }

        fn usedBitsCount(size_class: usize) usize {
            const slot_count = @divExact(page_size, size_class);
            if (slot_count < 8) return 1;
            return @divExact(slot_count, 8);
        }

        fn detectLeaksInBucket(
            bucket: *BucketHeader,
            size_class: usize,
            used_bits_count: usize,
        ) bool {
            var leaks = false;
            var used_bits_byte: usize = 0;
            while (used_bits_byte < used_bits_count) : (used_bits_byte += 1) {
                const used_byte = bucket.usedBits(used_bits_byte).*;
                if (used_byte != 0) {
                    var bit_index: u3 = 0;
                    while (true) : (bit_index += 1) {
                        const is_used = @truncate(u1, used_byte >> bit_index) != 0;
                        if (is_used) {
                            const slot_index = @intCast(SlotIndex, used_bits_byte * 8 + bit_index);
                            const stack_trace = bucketStackTrace(bucket, size_class, slot_index, .alloc);
                            const addr = bucket.page + slot_index * size_class;
                            // KLECKO
                            log.err("memory address 0x{x} leaked\n", .{@ptrToInt(addr)});
                            // log.err("memory address 0x{x} leaked: {s}", .{
                            //     @ptrToInt(addr), stack_trace,
                            // });
                            leaks = true;
                        }
                        if (bit_index == math.maxInt(u3))
                            break;
                    }
                }
            }
            return leaks;
        }

        /// Emits log messages for leaks and then returns whether there were any leaks.
        pub fn detectLeaks(self: *Self) bool {
            var leaks = false;
            for (self.buckets) |optional_bucket, bucket_i| {
                const first_bucket = optional_bucket orelse continue;
                const size_class = @as(usize, 1) << @intCast(math.Log2Int(usize), bucket_i);
                const used_bits_count = usedBitsCount(size_class);
                var bucket = first_bucket;
                while (true) {
                    leaks = detectLeaksInBucket(bucket, size_class, used_bits_count) or leaks;
                    bucket = bucket.next;
                    if (bucket == first_bucket)
                        break;
                }
            }
            var it = self.large_allocations.valueIterator();
            while (it.next()) |large_alloc| {
                // KLECKO
                log.err("memory address 0x{x} leaked\n", .{@ptrToInt(large_alloc.bytes.ptr)});
                // log.err("memory address 0x{x} leaked: {s}", .{
                //     @ptrToInt(large_alloc.bytes.ptr), large_alloc.getStackTrace(),
                // });
                leaks = true;
            }
            return leaks;
        }

        pub fn deinit(self: *Self) bool {
            const leaks = if (config.safety) self.detectLeaks() else false;
            self.large_allocations.deinit(self.backing_allocator);
            self.* = undefined;
            return leaks;
        }

        fn collectStackTrace(first_trace_addr: usize, addresses: *[stack_n]usize) void {
            if (stack_n == 0) return;
            std.mem.set(usize, addresses, 0);
            var stack_trace = StackTrace{
                .instruction_addresses = addresses,
                .index = 0,
            };
            std.debug.captureStackTrace(first_trace_addr, &stack_trace);
        }

        fn allocSlot(self: *Self, size_class: usize, trace_addr: usize) Error![*]u8 {
            const bucket_index = math.log2(size_class);
            const first_bucket = self.buckets[bucket_index] orelse try self.createBucket(
                size_class,
                bucket_index,
            );
            var bucket = first_bucket;
            const slot_count = @divExact(page_size, size_class);
            while (bucket.alloc_cursor == slot_count) {
                const prev_bucket = bucket;
                bucket = prev_bucket.next;
                if (bucket == first_bucket) {
                    // make a new one
                    bucket = try self.createBucket(size_class, bucket_index);
                    bucket.prev = prev_bucket;
                    bucket.next = prev_bucket.next;
                    prev_bucket.next = bucket;
                    bucket.next.prev = bucket;
                }
            }
            // change the allocator's current bucket to be this one
            self.buckets[bucket_index] = bucket;

            const slot_index = bucket.alloc_cursor;
            bucket.alloc_cursor += 1;

            var used_bits_byte = bucket.usedBits(slot_index / 8);
            const used_bit_index: u3 = @intCast(u3, slot_index % 8); // TODO cast should be unnecessary
            used_bits_byte.* |= (@as(u8, 1) << used_bit_index);
            bucket.used_count += 1;
            bucket.captureStackTrace(trace_addr, size_class, slot_index, .alloc);
            return bucket.page + slot_index * size_class;
        }

        fn searchBucket(
            self: *Self,
            bucket_index: usize,
            addr: usize,
        ) ?*BucketHeader {
            const first_bucket = self.buckets[bucket_index] orelse return null;
            var bucket = first_bucket;
            while (true) {
                const in_bucket_range = (addr >= @ptrToInt(bucket.page) and
                    addr < @ptrToInt(bucket.page) + page_size);
                if (in_bucket_range) return bucket;
                bucket = bucket.prev;
                if (bucket == first_bucket) {
                    return null;
                }
                self.buckets[bucket_index] = bucket;
            }
        }

        /// This function assumes the object is in the large object storage regardless
        /// of the parameters.
        fn resizeLarge(
            self: *Self,
            old_mem: []u8,
            old_align: u29,
            new_size: usize,
            len_align: u29,
            ret_addr: usize,
        ) Error!usize {
            const entry = self.large_allocations.getEntry(@ptrToInt(old_mem.ptr)) orelse {
                if (config.safety) {
                    @panic("Invalid free");
                } else {
                    unreachable;
                }
            };

            if (config.safety and old_mem.len != entry.value_ptr.bytes.len) {
                var addresses: [stack_n]usize = [1]usize{0} ** stack_n;
                var free_stack_trace = StackTrace{
                    .instruction_addresses = &addresses,
                    .index = 0,
                };
                std.debug.captureStackTrace(ret_addr, &free_stack_trace);
                // KLECKO
                // log.err("Allocation size {d} bytes does not match free size {d}. Allocation: {s} Free: {s}", .{
                log.err("Allocation size {d} bytes does not match free size {d}.\n", .{
                    entry.value_ptr.bytes.len,
                    old_mem.len,
                    // entry.value_ptr.getStackTrace(),
                    // free_stack_trace,
                });
            }

            const result_len = try self.backing_allocator.resizeFn(self.backing_allocator, old_mem, old_align, new_size, len_align, ret_addr);

            if (result_len == 0) {
                if (config.verbose_log) {
                    log.info("large free {d} bytes at {*}", .{ old_mem.len, old_mem.ptr });
                }

                assert(self.large_allocations.remove(@ptrToInt(old_mem.ptr)));
                return 0;
            }

            if (config.verbose_log) {
                log.info("large resize {d} bytes at {*} to {d}", .{
                    old_mem.len, old_mem.ptr, new_size,
                });
            }
            entry.value_ptr.bytes = old_mem.ptr[0..result_len];
            collectStackTrace(ret_addr, &entry.value_ptr.stack_addresses);
            return result_len;
        }

        pub fn setRequestedMemoryLimit(self: *Self, limit: usize) void {
            self.requested_memory_limit = limit;
        }

        fn resize(
            allocator: *Allocator,
            old_mem: []u8,
            old_align: u29,
            new_size: usize,
            len_align: u29,
            ret_addr: usize,
        ) Error!usize {
            const self = @fieldParentPtr(Self, "allocator", allocator);
            log.debug("gpa resize: {*} {} to {}\n", .{ old_mem, old_mem.len, new_size });

            const held = self.mutex.acquire();
            defer held.release();

            const prev_req_bytes = self.total_requested_bytes;
            if (config.enable_memory_limit) {
                const new_req_bytes = prev_req_bytes + new_size - old_mem.len;
                if (new_req_bytes > prev_req_bytes and new_req_bytes > self.requested_memory_limit) {
                    return error.OutOfMemory;
                }
                self.total_requested_bytes = new_req_bytes;
            }
            errdefer if (config.enable_memory_limit) {
                self.total_requested_bytes = prev_req_bytes;
            };

            assert(old_mem.len != 0);

            const aligned_size = math.max(old_mem.len, old_align);
            if (aligned_size > largest_bucket_object_size) {
                return self.resizeLarge(old_mem, old_align, new_size, len_align, ret_addr);
            }
            const size_class_hint = math.ceilPowerOfTwoAssert(usize, aligned_size);

            var bucket_index = math.log2(size_class_hint);
            var size_class: usize = size_class_hint;
            const bucket = while (bucket_index < small_bucket_count) : (bucket_index += 1) {
                if (self.searchBucket(bucket_index, @ptrToInt(old_mem.ptr))) |bucket| {
                    break bucket;
                }
                size_class *= 2;
            } else {
                print("aligned: {} {}\n", .{ aligned_size, largest_bucket_object_size });
                return self.resizeLarge(old_mem, old_align, new_size, len_align, ret_addr);
            };
            const byte_offset = @ptrToInt(old_mem.ptr) - @ptrToInt(bucket.page);
            const slot_index = @intCast(SlotIndex, byte_offset / size_class);
            const used_byte_index = slot_index / 8;
            const used_bit_index = @intCast(u3, slot_index % 8);
            const used_byte = bucket.usedBits(used_byte_index);
            const is_used = @truncate(u1, used_byte.* >> used_bit_index) != 0;
            if (!is_used) {
                if (config.safety) {
                    const alloc_stack_trace = bucketStackTrace(bucket, size_class, slot_index, .alloc);
                    const free_stack_trace = bucketStackTrace(bucket, size_class, slot_index, .free);
                    var addresses: [stack_n]usize = [1]usize{0} ** stack_n;
                    var second_free_stack_trace = StackTrace{
                        .instruction_addresses = &addresses,
                        .index = 0,
                    };
                    std.debug.captureStackTrace(ret_addr, &second_free_stack_trace);
                    // log.err("Double free detected. Allocation: {s} First free: {s} Second free: {s}", .{
                    log.err("Double free detected.", .{
                        // alloc_stack_trace,
                        // free_stack_trace,
                        // second_free_stack_trace,
                    });
                    if (new_size == 0) {
                        // Recoverable. Restore self.total_requested_bytes if needed, as we
                        // don't return an error value so the errdefer above does not run.
                        if (config.enable_memory_limit) {
                            self.total_requested_bytes = prev_req_bytes;
                        }
                        return @as(usize, 0);
                    }
                    @panic("Unrecoverable double free");
                } else {
                    unreachable;
                }
            }
            if (new_size == 0) {
                // Capture stack trace to be the "first free", in case a double free happens.
                bucket.captureStackTrace(ret_addr, size_class, slot_index, .free);

                used_byte.* &= ~(@as(u8, 1) << used_bit_index);
                bucket.used_count -= 1;
                if (bucket.used_count == 0) {
                    if (bucket.next == bucket) {
                        // it's the only bucket and therefore the current one
                        self.buckets[bucket_index] = null;
                    } else {
                        bucket.next.prev = bucket.prev;
                        bucket.prev.next = bucket.next;
                        self.buckets[bucket_index] = bucket.prev;
                    }
                    if (!config.never_unmap) {
                        self.backing_allocator.free(bucket.page[0..page_size]);
                    }
                    const bucket_size = bucketSize(size_class);
                    const bucket_slice = @ptrCast([*]align(@alignOf(BucketHeader)) u8, bucket)[0..bucket_size];
                    self.backing_allocator.free(bucket_slice);
                } else {
                    @memset(old_mem.ptr, undefined, old_mem.len);
                }
                if (config.verbose_log) {
                    log.info("small free {d} bytes at {*}", .{ old_mem.len, old_mem.ptr });
                }
                return @as(usize, 0);
            }
            const new_aligned_size = math.max(new_size, old_align);
            const new_size_class = math.ceilPowerOfTwoAssert(usize, new_aligned_size);
            if (new_size_class <= size_class) {
                if (old_mem.len > new_size) {
                    @memset(old_mem.ptr + new_size, undefined, old_mem.len - new_size);
                }
                if (config.verbose_log) {
                    log.info("small resize {d} bytes at {*} to {d}", .{
                        old_mem.len, old_mem.ptr, new_size,
                    });
                }
                return new_size;
            }
            return error.OutOfMemory;
        }

        // Returns true if an allocation of `size` bytes is within the specified
        // limits if enable_memory_limit is true
        fn isAllocationAllowed(self: *Self, size: usize) bool {
            if (config.enable_memory_limit) {
                const new_req_bytes = self.total_requested_bytes + size;
                if (new_req_bytes > self.requested_memory_limit)
                    return false;
                self.total_requested_bytes = new_req_bytes;
            }

            return true;
        }

        fn alloc(allocator: *Allocator, len: usize, ptr_align: u29, len_align: u29, ret_addr: usize) Error![]u8 {
            log.debug("gpa alloc: {}\n", .{len});
            const self = @fieldParentPtr(Self, "allocator", allocator);

            const held = self.mutex.acquire();
            defer held.release();

            const new_aligned_size = math.max(len, ptr_align);
            if (new_aligned_size > largest_bucket_object_size) {
                try self.large_allocations.ensureCapacity(
                    self.backing_allocator,
                    self.large_allocations.count() + 1,
                );

                const slice = try self.backing_allocator.allocFn(self.backing_allocator, len, ptr_align, len_align, ret_addr);

                // The backing allocator may return a memory block bigger than
                // `len`, use the effective size for bookkeeping purposes
                if (!self.isAllocationAllowed(slice.len)) {
                    // Free the block so no memory is leaked
                    const new_len = try self.backing_allocator.resizeFn(self.backing_allocator, slice, ptr_align, 0, 0, ret_addr);
                    assert(new_len == 0);
                    return error.OutOfMemory;
                }

                const gop = self.large_allocations.getOrPutAssumeCapacity(@ptrToInt(slice.ptr));
                assert(!gop.found_existing); // This would mean the kernel double-mapped pages.
                gop.value_ptr.bytes = slice;
                collectStackTrace(ret_addr, &gop.value_ptr.stack_addresses);

                if (config.verbose_log) {
                    log.info("large alloc {d} bytes at {*}", .{ slice.len, slice.ptr });
                }
                return slice;
            }

            if (!self.isAllocationAllowed(len)) {
                return error.OutOfMemory;
            }

            const new_size_class = math.ceilPowerOfTwoAssert(usize, new_aligned_size);
            const ptr = try self.allocSlot(new_size_class, ret_addr);
            if (config.verbose_log) {
                log.info("small alloc {d} bytes at {*}", .{ len, ptr });
            }
            return ptr[0..len];
        }

        fn createBucket(self: *Self, size_class: usize, bucket_index: usize) Error!*BucketHeader {
            const page = try self.backing_allocator.allocAdvanced(u8, page_size, page_size, .exact);
            errdefer self.backing_allocator.free(page);

            const bucket_size = bucketSize(size_class);
            const bucket_bytes = try self.backing_allocator.allocAdvanced(u8, @alignOf(BucketHeader), bucket_size, .exact);
            const ptr = @ptrCast(*BucketHeader, bucket_bytes.ptr);
            ptr.* = BucketHeader{
                .prev = ptr,
                .next = ptr,
                .page = page.ptr,
                .alloc_cursor = 0,
                .used_count = 0,
            };
            self.buckets[bucket_index] = ptr;
            // Set the used bits to all zeroes
            @memset(@as(*[1]u8, ptr.usedBits(0)), 0, usedBitsCount(size_class));
            return ptr;
        }
    };
}

const TraceKind = enum {
    alloc,
    free,
};
