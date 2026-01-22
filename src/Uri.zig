//! https://url.spec.whatwg.org/#url-representation

const std = @import("std");

const Uri = @This();

scheme: []const u8,
username: ?[]const u8,
password: ?[]const u8,
host: ?[]const u8,
port: ?u16,
path: Path,
query: ?[]const u8,
fragment: ?[]const u8,
blob: ?Blob,

/// https://url.spec.whatwg.org/#url-path
pub const Path = union(enum) {
    opaque_path: Segment,
    list: []Segment,

    pub const Segment = struct {};
};

/// https://w3c.github.io/FileAPI/#blob-url-entry
pub const Blob = @compileError("TODO: Blob");

pub const ParseError = error{};

/// https://url.spec.whatwg.org/#url-parsing
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
