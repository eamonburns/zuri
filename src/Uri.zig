//! https://url.spec.whatwg.org/#url-representation

const std = @import("std");
const Allocator = std.mem.Allocator;

const Uri = @This();

/// A URI’s `scheme` is an ASCII string that identifies the type of URI and can be used to dispatch a URI for further processing after parsing. It is initially the empty string.
/// <https://url.spec.whatwg.org/#concept-url-scheme>
scheme: []const u8,
/// A URI’s `username` is an ASCII string identifying a username. It is initially _null_ (edit)
/// <https://url.spec.whatwg.org/#concept-url-username>
username: ?[]const u8,
/// A URI’s `password` is an ASCII string identifying a password. It is initially _null_ (edit)
/// <https://url.spec.whatwg.org/#concept-url-password>
password: ?[]const u8,
/// A URI’s `host` is null or a [Host]. It is initially null.
/// <https://url.spec.whatwg.org/#concept-url-host>
host: ?Host,
/// A URI’s `port` is either null or a 16-bit unsigned integer that identifies a networking port. It is initially null.
/// <https://url.spec.whatwg.org/#concept-url-port>
port: ?u16,
/// A URI’s `path` is a [Path], usually identifying a location. It is initially _an empty list_ (edit)
/// <https://url.spec.whatwg.org/#concept-url-path>
path: Path,
/// A URI’s `query` is either null or an ASCII string. It is initially null.
/// <https://url.spec.whatwg.org/#concept-url-query>
query: ?[]const u8,
/// A URI’s `fragment` is either null or an ASCII string that can be used for further processing on the resource the URI’s other components identify. It is initially null.
/// <https://url.spec.whatwg.org/#concept-url-fragment>
fragment: ?[]const u8,

const init: Uri = .{
    .scheme = "",
    .username = null,
    .password = null,
    .host = null,
    .port = null,
    .path = .{ .list = &.{} },
    .query = null,
    .fragment = null,
};

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

pub const Encoding = enum { utf8 };

pub const ParseError = error{};

/// https://url.spec.whatwg.org/#url-parsing
pub fn parse(gpa: Allocator, input: []const u8) ParseError!Uri {
    return parseExtended(gpa, input, null, null);
}

/// https://url.spec.whatwg.org/#url-parsing
pub fn parseExtended(gpa: Allocator, input: []const u8, base: ?Uri, opt_encoding: ?Encoding) ParseError!Uri {
    const uri = try parseImpl(gpa, input, base, opt_encoding);
    if (!std.mem.eql(u8, uri.scheme, "blob")) return uri;

    // TODO: Blob entry
    // https://url.spec.whatwg.org/#concept-url-blob-entry
    return uri;
}

/// https://url.spec.whatwg.org/#concept-basic-url-parser
fn parseImpl(
    gpa: Allocator,
    input: []const u8,
    base: ?Uri,
    opt_encoding: ?Encoding,
    // TODO: modify Uri
    // https://url.spec.whatwg.org/#basic-url-parser-url
    // TODO: state override
    // https://url.spec.whatwg.org/#basic-url-parser-state-override
) ParseError!Uri {
    _ = input;
    _ = base;
    const uri: Uri = .init;

    // NOTE:
    // - "If `input` contains any ASCII tab or newline, invalid-URL-unit validation error"
    // - "Remove all ASCII tab or newline from input."
    // Each tab or newline will need to be removed individually, rather than removing them all at once at the start

    const State = enum {
        /// <https://url.spec.whatwg.org/#scheme-start-state>
        scheme_start,
        /// <https://url.spec.whatwg.org/#scheme-state>
        scheme,
        /// <https://url.spec.whatwg.org/#no-scheme-state>
        no_scheme,
        /// <https://url.spec.whatwg.org/#special-relative-or-authority-state>
        special_relative_or_authority,
        /// <https://url.spec.whatwg.org/#path-or-authority-state>
        path_or_authority,
        /// <https://url.spec.whatwg.org/#relative-state>
        relative,
        /// <https://url.spec.whatwg.org/#relative-slash-state>
        relative_slash,
        /// <https://url.spec.whatwg.org/#special-authority-slashes-state>
        special_authority_slashes,
        /// <https://url.spec.whatwg.org/#special-authority-ignore-slashes-state>
        special_authority_ignore_slashes,
        /// <https://url.spec.whatwg.org/#authority-state>
        authority,
        /// <https://url.spec.whatwg.org/#host-state>
        host,
        /// <https://url.spec.whatwg.org/#hostname-state>
        hostname,
        /// <https://url.spec.whatwg.org/#port-state>
        port,
        /// <https://url.spec.whatwg.org/#file-state>
        file,
        /// <https://url.spec.whatwg.org/#file-slash-state>
        file_slash,
        /// <https://url.spec.whatwg.org/#file-host-state>
        file_host,
        /// <https://url.spec.whatwg.org/#path-start-state>
        path_start,
        /// <https://url.spec.whatwg.org/#path-state>
        path,
        /// <https://url.spec.whatwg.org/#cannot-be-a-base-url-path-state>
        opaque_path,
        /// <https://url.spec.whatwg.org/#query-state>
        query,
        /// <https://url.spec.whatwg.org/#fragment-state>
        fragment,
    };
    var state: State = .scheme_start;
    _ = &state;
    const encoding = opt_encoding orelse .utf8;
    _ = encoding;

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(gpa);

    var at_sign_seen, var inside_brackets, var password_token_seen = .{ false, false, false };
    _ = &at_sign_seen;
    _ = &inside_brackets;
    _ = &password_token_seen;
    var pointer: usize = 0;
    _ = &pointer;

    // "Keep running the following state machine by switching on state. If after a run pointer points to the EOF code point, go to the next step. Otherwise, increase pointer by 1 and continue with the state machine."
    switch (state) {
        else => return uri,
    }
}

pub fn format(
    self: Uri,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    _ = self;
    try writer.writeAll("<unknown>");
}
