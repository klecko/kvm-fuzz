pub const file_manager = @import("file_manager.zig");

const file_description = @import("file_description.zig");
pub const FileDescription = file_description.FileDescription;
pub const statRegular = file_description.statRegular;
pub const statStdin = file_description.statStdin;
pub const statStdout = file_description.statStdout;
