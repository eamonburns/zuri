const std = @import("std");

const Uri = @This();

pub const ParseError = error{};

pub fn parse(input: []const u8) ParseError!Uri {
    _ = input;
    return .{};
}

pub fn format(
    self: Uri,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    _ = self;
    try writer.writeAll("<unknown>");
}
