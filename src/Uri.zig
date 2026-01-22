//! https://url.spec.whatwg.org/#url-representation

const std = @import("std");

const Uri = @This();

scheme: []const u8,
username: ?[]const u8,
password: ?[]const u8,
host: ?Host,
port: ?u16,
path: Path,
query: ?[]const u8,
fragment: ?[]const u8,

/// https://url.spec.whatwg.org/#host-representation
pub const Host = union(enum) {
    domain: []const u8,
    ip_address: union(enum) {
        ip4: Ip4Address,
        ip6: Ip6Address,
    },
    opaque_host: []const u8,
    empty,

    pub const Ip4Address = packed struct(u32) {
        segment0: u8,
        segment1: u8,
        segment2: u8,
        segment3: u8,
    };
    pub const Ip6Address = packed struct(u128) {
        segment0: u16,
        segment1: u16,
        segment2: u16,
        segment3: u16,
        segment4: u16,
        segment5: u16,
        segment6: u16,
        segment7: u16,
    };
};

/// https://url.spec.whatwg.org/#url-path
pub const Path = union(enum) {
    opaque_path: Segment,
    list: []Segment,

    pub const Segment = struct {};
};

/// NOTE: Not implemented
/// https://w3c.github.io/FileAPI/#blob-url-entry
pub const Blob = @compileError("unimplemented: Blob");

pub const ParseError = error{};

/// https://url.spec.whatwg.org/#url-parsing
pub fn parse(input: []const u8) ParseError!Uri {
    _ = input;
    return .{
        .scheme = "",
        .username = null,
        .password = null,
        .host = null,
        .port = null,
        .path = .{ .list = &.{} },
        .query = null,
        .fragment = null,
    };
}

pub fn format(
    self: Uri,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    _ = self;
    try writer.writeAll("<unknown>");
}
