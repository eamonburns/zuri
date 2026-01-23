//! <https://url.spec.whatwg.org/#url-representation>

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

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

/// <https://url.spec.whatwg.org/#host-representation>
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

/// <https://url.spec.whatwg.org/#url-path>
pub const Path = union(enum) {
    opaque_path: Segment,
    list: []Segment,

    pub const Segment = []const u8;
};

/// NOTE: Not (currently) implemented
/// <https://w3c.github.io/FileAPI/#blob-url-entry>
pub const Blob = @compileError("unimplemented: Blob");

pub const Encoding = enum { utf8 };

pub const ParseError = error{} || Allocator.Error;

/// <https://url.spec.whatwg.org/#url-parsing>
pub fn parse(gpa: Allocator, input: []const u8) ParseError!Uri {
    return parseExtended(gpa, input, null, null);
}

/// <https://url.spec.whatwg.org/#url-parsing>
pub fn parseExtended(gpa: Allocator, input: []const u8, base: ?Uri, opt_encoding: ?Encoding) ParseError!Uri {
    const uri = try parseImpl(gpa, input, base, opt_encoding);
    if (!std.mem.eql(u8, uri.scheme, "blob")) return uri;

    // TODO: Blob entry
    // https://url.spec.whatwg.org/#concept-url-blob-entry
    return uri;
}

/// <https://url.spec.whatwg.org/#concept-basic-url-parser>
fn parseImpl(
    gpa: Allocator,
    input: []const u8,
    base: ?Uri,
    opt_encoding: ?Encoding,
    // TODO: modify Uri
    // <https://url.spec.whatwg.org/#basic-url-parser-url>
    // TODO: state override
    // <https://url.spec.whatwg.org/#basic-url-parser-state-override>
) ParseError!Uri {
    var uri: Uri = .init;

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
    // <https://url.spec.whatwg.org/#pointer>
    var pointer: usize = 0;
    _ = &pointer;

    // "Keep running the following state machine by switching on state. If after a run pointer points to the EOF code point, go to the next step. Otherwise, increase pointer by 1 and continue with the state machine."
    while (true) : (pointer += 1) {
        switch (state) {
            .scheme_start => {
                const c = codepoint(pointer, input) orelse 0;

                if (std.ascii.isAlphabetic(c)) {
                    // "If c is an ASCII alpha, append c, lowercased, to buffer, and set state to scheme state."
                    try buffer.append(gpa, std.ascii.toLower(input[pointer]));
                    state = .scheme;
                } else {
                    // "Otherwise, if state override is not given, set state to no scheme state and decrease pointer by 1." (NOTE: there is no "state override", so this always succeeds)
                    state = .no_scheme;
                    pointer -= 1;
                }
            },
            .scheme => {
                const c = codepoint(pointer, input) orelse 0;
                if (std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.') {
                    // "If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.), append c, lowercased, to buffer."
                    try buffer.append(gpa, std.ascii.toLower(input[pointer]));
                } else if (c == ':') {
                    // "Otherwise, if c is U+003A (:)"

                    if (false) {
                        // "If state override is given" (NOTE: there is no "state override", so this always fails)

                        if (isSpecialScheme(uri.scheme) != isSpecialScheme(buffer.items)) {
                            // "If url’s scheme is a special scheme and buffer is not a special scheme, then return."
                            // "If url’s scheme is not a special scheme and buffer is a special scheme, then return."

                            return uri;
                        } else if ((uri.username != null or uri.password != null or uri.port != null) and std.mem.eql(u8, buffer.items, "file")) {
                            // "If url includes credentials or has a non-null port, and buffer is "file", then return."

                            return uri;
                        } else if (std.mem.eql(u8, uri.scheme, "file") and uri.host == .empty) {
                            // "If url’s scheme is "file" and its host is an empty host, then return."

                            return uri;
                        }
                    }
                    // "Set url’s scheme to buffer."
                    uri.scheme = try buffer.toOwnedSlice(gpa);
                    if (false) {
                        // "If state override is given" (NOTE: there is no "state override", so this always fails)

                        if (uri.port == schemeDefaultPort(uri.scheme)) {
                            // "If url’s port is url’s scheme’s default port, then set url’s port to null."

                            uri.port = null;
                        }
                        return uri;
                    }
                    // "Set buffer to the empty string."
                    buffer.clearRetainingCapacity();
                    if (std.mem.eql(u8, uri.scheme, "file")) {
                        if (!std.mem.startsWith(u8, remaining(pointer, input), "//")) {
                            // "If remaining does not start with "//", special-scheme-missing-following-solidus validation error."
                            // TODO: Validation error
                            std.debug.print("Validation error: special-scheme-missing-following-solidus\n", .{});
                        }
                        state = .file;
                    } else if (isSpecialScheme(uri.scheme) and base != null and std.mem.eql(u8, base.?.scheme, uri.scheme)) {
                        // "Otherwise, if url is special, base is non-null, and base’s scheme is url’s scheme"

                        // "Assert: base is special (and therefore does not have an opaque path)"
                        assert(isSpecialScheme(base.?.scheme) and base.?.path != .opaque_path);

                        // "Set state to special relative or authority state."
                        state = .special_relative_or_authority;
                    } else if (isSpecialScheme(uri.scheme)) {
                        // "Otherwise, if url is special, set state to special authority slashes state"
                        state = .special_authority_slashes;
                    } else if (std.mem.startsWith(u8, remaining(pointer, input), "/")) {
                        // "Otherwise, if remaining starts with an U+002F (/), set state to path or authority state and increase pointer by 1"
                        state = .path_or_authority;
                        pointer += 1;
                    } else {
                        // "Otherwise, set url’s path to the empty string and set state to opaque path state"
                        uri.path = .{ .opaque_path = "" };
                        state = .opaque_path;
                    }
                } else if (true) {
                    // "Otherwise, if state override is not given, set buffer to the empty string, state to no scheme state, and start over (from the first code point in input)." (NOTE: there is no "state override", so this always succeeds)
                    buffer.clearRetainingCapacity();
                    state = .no_scheme;
                    // FIXME: I don't think this quite works. It should either be set to -1, and then it is set to 0 by the while loop continue expression, or we should skip the continue expression somehow
                    pointer = 0;
                } else {
                    // "Otherwise, return failure"
                    return error.ParseFailure;
                }
            },
            inline else => |s| @panic("TODO: " ++ @tagName(s)),
        }

        if (codepoint(pointer, input) == null) break;
    }

    return uri;
}

/// <https://url.spec.whatwg.org/#c>
fn codepoint(pointer: usize, input: []const u8) ?u8 {
    if (pointer >= input.len) return null;
    return input[pointer];
}

/// <https://url.spec.whatwg.org/#remaining>
fn remaining(pointer: usize, input: []const u8) []const u8 {
    assert(codepoint(pointer, input) != null);

    return input[pointer + 1 ..];
}

pub const SpecialScheme = enum {
    ftp,
    file,
    http,
    https,
    ws,
    wss,
};

/// <https://url.spec.whatwg.org/#special-scheme>
fn isSpecialScheme(scheme: []const u8) bool {
    return std.meta.stringToEnum(SpecialScheme, scheme) != null;
}

/// <https://url.spec.whatwg.org/#default-port>
fn schemeDefaultPort(scheme: []const u8) ?u16 {
    const special_scheme = std.meta.stringToEnum(SpecialScheme, scheme) orelse return null;
    return switch (special_scheme) {
        .ftp => 22,
        .file => null,
        .http => 80,
        .https => 443,
        .ws => 80,
        .wss => 443,
    };
}

pub fn format(
    self: Uri,
    writer: *std.Io.Writer,
) std.Io.Writer.Error!void {
    _ = self;
    try writer.writeAll("<unknown>");
}
