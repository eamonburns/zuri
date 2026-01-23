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

pub fn deinit(uri: Uri, gpa: Allocator) void {
    gpa.free(uri.scheme);
    if (uri.username) |u| gpa.free(u);
    if (uri.password) |p| gpa.free(p);
    if (uri.host) |h| h.deinit(gpa);
    uri.path.deinit(gpa);
    if (uri.query) |q| gpa.free(q);
    if (uri.fragment) |f| gpa.free(f);
}

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

    pub fn deinit(host: Host, gpa: Allocator) void {
        switch (host) {
            .domain => |d| gpa.free(d),
            .opaque_host => |oh| gpa.free(oh),
            .ip_address, .empty => {},
        }
    }
};

/// <https://url.spec.whatwg.org/#url-path>
pub const Path = union(enum) {
    opaque_path: Segment,
    list: []Segment,

    pub const Segment = []const u8;

    pub fn dupe(p: Path, gpa: Allocator) Allocator.Error!Path {
        switch (p) {
            .opaque_path => |op| return .{ .opaque_path = try gpa.dupe(u8, op) },
            .list => |l| {
                const list: []Segment = try gpa.alloc(Segment, l.len);
                errdefer gpa.free(list);

                for (list, 0..) |*s, i| {
                    s.* = try gpa.dupe(u8, l[i]);
                }
                return .{ .list = list };
            },
        }
    }

    pub fn deinit(p: Path, gpa: Allocator) void {
        switch (p) {
            .opaque_path => |op| gpa.free(op),
            .list => |l| {
                for (l) |s| {
                    gpa.free(s);
                }
                gpa.free(l);
            },
        }
    }
};

/// NOTE: Not (currently) implemented
/// <https://w3c.github.io/FileAPI/#blob-url-entry>
pub const Blob = @compileError("unimplemented: Blob");

pub const Encoding = enum { utf8 };

pub const ParseError = error{ ParseFailure, Validation } || Allocator.Error;

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
    errdefer uri.deinit(gpa);

    // NOTE:
    // - "If `input` contains any ASCII tab or newline, invalid-URL-unit validation error"
    // - "Remove all ASCII tab or newline from input."
    // Each tab or newline will need to be removed individually, rather than removing them all at once at the start

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

    var pointer: Pointer = .init(input);

    const validation_error_behavior: ValidationError.Behavior = .continue_parsing;

    // "Keep running the following state machine by switching on state. If after a run pointer points to the EOF code point, go to the next step. Otherwise, increase pointer by 1 and continue with the state machine."
    while (true) : (pointer.inc()) {
        if (pointer.codepoint() == '\t' or pointer.codepoint() == '\n') {
            try validationError(.invalid_url_unit, validation_error_behavior);
            pointer.inc();
            continue;
        }

        switch (state) {
            .scheme_start => {
                const c = pointer.codepoint() orelse 0;

                if (std.ascii.isAlphabetic(c)) {
                    // "If c is an ASCII alpha, append c, lowercased, to buffer, and set state to 'scheme' state."
                    try buffer.append(gpa, std.ascii.toLower(c));
                    state = .scheme;
                } else {
                    // "Otherwise, if state override is not given, set state to 'no scheme' state and decrease pointer by 1." (NOTE: there is no "state override", so this always succeeds)
                    state = .no_scheme;
                    pointer.dec();
                }
            },
            .scheme => {
                const c = pointer.codepoint() orelse 0;
                if (std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.') {
                    // "If c is an ASCII alphanumeric, U+002B (+), U+002D (-), or U+002E (.), append c, lowercased, to buffer."
                    try buffer.append(gpa, std.ascii.toLower(c));
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
                        if (!std.mem.startsWith(u8, pointer.remaining(), "//")) {
                            // "If remaining does not start with "//", special-scheme-missing-following-solidus validation error."
                            try validationError(.special_scheme_missing_following_solidus, validation_error_behavior);
                        }
                        state = .file;
                    } else if (isSpecialScheme(uri.scheme) and base != null and std.mem.eql(u8, base.?.scheme, uri.scheme)) {
                        // "Otherwise, if url is special, base is non-null, and base’s scheme is url’s scheme"

                        // "Assert: base is special (and therefore does not have an opaque path)"
                        assert(isSpecialScheme(base.?.scheme) and base.?.path != .opaque_path);

                        // "Set state to 'special relative or authority' state."
                        state = .special_relative_or_authority;
                    } else if (isSpecialScheme(uri.scheme)) {
                        // "Otherwise, if url is special, set state to 'special authority slashes' state"
                        state = .special_authority_slashes;
                    } else if (std.mem.startsWith(u8, pointer.remaining(), "/")) {
                        // "Otherwise, if remaining starts with an U+002F (/), set state to 'path or authority' state and increase pointer by 1"
                        state = .path_or_authority;
                        pointer.inc();
                    } else {
                        // "Otherwise, set url’s path to the empty string and set state to 'opaque path' state"
                        uri.path = .{ .opaque_path = "" };
                        state = .opaque_path;
                    }
                } else if (true) {
                    // "Otherwise, if state override is not given, set buffer to the empty string, state to 'no scheme' state, and start over (from the first code point in input)." (NOTE: there is no "state override", so this always succeeds)
                    buffer.clearRetainingCapacity();
                    state = .no_scheme;
                    // FIXME: I don't think this quite works. It should either be set to -1, and then it is set to 0 by the while loop continue expression, or we should skip the continue expression somehow
                    pointer.index = Pointer.negative_one;
                } else {
                    // "Otherwise, return failure"
                    return error.ParseFailure;
                }
            },
            .no_scheme => {
                const c = pointer.codepoint() orelse 0;
                if (base == null or (base.?.path == .opaque_path and c != '#')) {
                    // "If base is null, or base has an opaque path and c is not U+0023 (#), missing-scheme-non-relative-URL validation error, return failure"
                    try validationError(.missing_scheme_non_relative_url, validation_error_behavior);
                    return error.ParseFailure;
                } else if (base.?.path == .opaque_path and c == '#') {
                    // "Otherwise, if base has an opaque path and c is U+0023 (#), set url’s scheme to base’s scheme, url’s path to base’s path, url’s query to base’s query, url’s fragment to the empty string, and set state to fragment state."
                    uri.scheme = try gpa.dupe(u8, base.?.scheme);
                    uri.path = try base.?.path.dupe(gpa);
                    if (base.?.query) |q| {
                        uri.query = try gpa.dupe(u8, q);
                    } else uri.query = null;
                    uri.fragment = "";
                    state = .fragment;
                } else if (!std.mem.eql(u8, base.?.scheme, "file")) {
                    // "Otherwise, if base’s scheme is not "file", set state to 'relative state' and decrease pointer by 1"
                    state = .relative;
                    pointer.dec();
                } else {
                    // "Otherwise, set state to file state and decrease pointer by 1"
                    state = .file;
                    pointer.dec();
                }
            },
            .special_relative_or_authority => {
                const c = pointer.codepoint() orelse 0;
                if (c == '/' and std.mem.startsWith(u8, pointer.remaining(), "/")) {
                    // "If c is U+002F (/) and remaining starts with U+002F (/), then set state to 'special authority ignore slashes' state and increase pointer by 1"
                    state = .special_authority_ignore_slashes;
                    pointer.inc();
                } else {
                    // "Otherwise, special-scheme-missing-following-solidus validation error, set state to 'relative' state and decrease pointer by 1"
                    try validationError(.special_scheme_missing_following_solidus, validation_error_behavior);
                    state = .relative;
                    pointer.dec();
                }
            },
            inline else => |s| @panic("TODO: '" ++ @tagName(s) ++ "' state"),
        }

        if (!pointer.pointsNowhere() and pointer.codepoint() == null) break;
    }

    return uri;
}

pub const ValidationError = enum {
    /// Unicode ToASCII records an error or returns the empty string. [UTS46]
    /// Example:
    /// Failure: Yes
    domain_to_ascii,
    /// The input’s host contains a forbidden domain code point.
    /// Example: Hosts are percent-decoded before being processed when the URL is special, which would result in the following host portion becoming "exa#mple.org" and thus triggering this error. "https://exa%23mple.org"
    /// Failure: Yes
    domain_invalid_code_point,
    /// Unicode ToUnicode records an error. [UTS46]
    /// Example:
    /// Failure: No
    domain_to_unicode,
    /// An opaque host (in a URL that is not special) contains a forbidden host code point.
    /// Example: "foo://exa[mple.org"
    /// Failure: Yes
    host_invalid_code_point,
    /// An IPv4 address ends with a U+002E (.).
    /// Example: "https://127.0.0.1./"
    /// Failure: No
    ipv4_empty_part,
    /// An IPv4 address does not consist of exactly 4 parts.
    /// Example: "https://1.2.3.4.5/"
    /// Failure: Yes
    ipv4_too_many_parts,
    /// An IPv4 address part is not numeric.
    /// Example: "https://test.42"
    /// Failure: Yes
    ipv4_non_numeric_part,
    /// The IPv4 address contains numbers expressed using hexadecimal or octal digits.
    /// Example: "https://127.0.0x0.1"
    /// Failure: No
    ipv4_non_decimal_part,
    /// An IPv4 address part exceeds 255.
    /// Example: "https://255.255.4000.1"
    /// Failure: Yes (only if applicable to the last part)
    ipv4_out_of_range_part,
    /// An IPv6 address is missing the closing U+005D (]).
    /// Example: "https://[::1"
    /// Failure: Yes
    ipv6_unclosed,
    /// An IPv6 address begins with improper compression.
    /// Example: "https://[:1]"
    /// Failure: Yes
    ipv6_invalid_compression,
    /// An IPv6 address contains more than 8 pieces.
    /// Example: "https://[1:2:3:4:5:6:7:8:9]"
    /// Failure: Yes
    ipv6_too_many_pieces,
    /// An IPv6 address is compressed in more than one spot.
    /// Example: "https://[1::1::1]"
    /// Failure: Yes
    ipv6_multiple_compression,
    /// An IPv6 address contains a code point that is neither an ASCII hex digit nor a U+003A (:). Or it unexpectedly ends.
    /// Example: "https://[1:2:3!:4]" "https://[1:2:3:]"
    /// Failure: Yes
    ipv6_invalid_code_point,
    /// An uncompressed IPv6 address contains fewer than 8 pieces.
    /// Example: "https://[1:2:3]"
    /// Failure: Yes
    ipv6_too_few_pieces,
    /// An IPv6 address with IPv4 address syntax: the IPv6 address has more than 6 pieces.
    /// Example: "https://[1:1:1:1:1:1:1:127.0.0.1]"
    /// Failure: Yes
    ipv4_in_ipv6_too_many_pieces,
    /// An IPv6 address with IPv4 address syntax: An IPv4 part is empty or contains a non-ASCII digit. An IPv4 part contains a leading 0. There are too many IPv4 parts.
    /// Example: "https://[ffff::.0.0.1]" "https://[ffff::127.0.xyz.1]" "https://[ffff::127.0xyz]" "https://[ffff::127.00.0.1]" "https://[ffff::127.0.0.1.2]"
    /// Failure: Yes
    ipv4_in_ipv6_invalid_code_point,
    /// An IPv6 address with IPv4 address syntax: an IPv4 part exceeds 255.
    /// Example: "https://[ffff::127.0.0.4000]"
    /// Failure: Yes
    ipv4_in_ipv6_out_of_range_part,
    /// An IPv6 address with IPv4 address syntax: an IPv4 address contains too few parts.
    /// Example: "https://[ffff::127.0.0]"
    /// Failure: Yes
    ipv4_in_ipv6_too_few_parts,
    /// A code point is found that is not a URL unit.
    /// Example: "https://example.org/>" " https://example.org " "ht\ntps://example.org" "https://example.org/%s"
    /// Failure: No
    invalid_url_unit,
    /// The input’s scheme is not followed by "//".
    /// Example: "file:c:/my-secret-folder" "https:example.org" `const url = new URL("https:foo.html", "https://example.org/");`
    /// Failure: No
    special_scheme_missing_following_solidus,
    /// The input is missing a scheme, because it does not begin with an ASCII alpha, and either no base URL was provided or the base URL cannot be used as a base URL because it has an opaque path.
    /// Example: Input’s scheme is missing and no base URL is given: `const url = new URL("💩");`. Input’s scheme is missing, but the base URL has an opaque path: `const url = new URL("💩", "mailto:user@example.org");`
    /// Failure: Yes
    missing_scheme_non_relative_url,
    /// The URL has a special scheme and it uses U+005C (\) instead of U+002F (/).
    /// Example: "https://example.org\path\to\file"
    /// Failure: No
    invalid_reverse_solidus,
    /// The input includes credentials.
    /// Example: "https://user@example.org" "ssh://user@example.org"
    /// Failure: No
    invalid_credentials,
    /// The input has a special scheme, but does not contain a host.
    /// Example: "https://#fragment" "https://:443" "https://user:pass@"
    /// Failure: Yes
    host_missing,
    /// The input’s port is too big.
    /// Example: "https://example.org:70000"
    /// Failure: Yes
    port_out_of_range,
    /// The input’s port is invalid.
    /// Example: "https://example.org:7z"
    /// Failure: Yes
    port_invalid,
    /// The input is a relative-URL string that starts with a Windows drive letter and the base URL’s scheme is "file".
    /// Example: `const url = new URL("/c:/path/to/file", "file:///c:/");`
    /// Failure: No
    file_invalid_windows_drive_letter,
    /// A file: URL’s host is a Windows drive letter.
    /// Example: "file://c:"
    /// Failure: No
    file_invalid_windows_drive_letter_host,

    pub const Behavior = enum {
        /// Report error and stop parsing
        fail_parsing,
        /// Report error and continue parsing
        continue_parsing,
        /// Don't report error and continue parsing
        silent,
    };

    pub fn description(err: ValidationError) []const u8 {
        return switch (err) {
            .domain_to_ascii => "Unicode ToASCII records an error or returns the empty string. [UTS46]",
            .domain_invalid_code_point => "The input’s host contains a forbidden domain code point.",
            .domain_to_unicode => "Unicode ToUnicode records an error. [UTS46]",
            .host_invalid_code_point => "An opaque host (in a URL that is not special) contains a forbidden host code point.",
            .ipv4_empty_part => "An IPv4 address ends with a U+002E (.).",
            .ipv4_too_many_parts => "An IPv4 address does not consist of exactly 4 parts.",
            .ipv4_non_numeric_part => "An IPv4 address part is not numeric.",
            .ipv4_non_decimal_part => "The IPv4 address contains numbers expressed using hexadecimal or octal digits.",
            .ipv4_out_of_range_part => "An IPv4 address part exceeds 255.",
            .ipv6_unclosed => "An IPv6 address is missing the closing U+005D (]).",
            .ipv6_invalid_compression => "An IPv6 address begins with improper compression.",
            .ipv6_too_many_pieces => "An IPv6 address contains more than 8 pieces.",
            .ipv6_multiple_compression => "An IPv6 address is compressed in more than one spot.",
            .ipv6_invalid_code_point => "An IPv6 address contains a code point that is neither an ASCII hex digit nor a U+003A (:). Or it unexpectedly ends.",
            .ipv6_too_few_pieces => "An uncompressed IPv6 address contains fewer than 8 pieces.",
            .ipv4_in_ipv6_too_many_pieces => "An IPv6 address with IPv4 address syntax: the IPv6 address has more than 6 pieces.",
            .ipv4_in_ipv6_invalid_code_point => "An IPv6 address with IPv4 address syntax: An IPv4 part is empty or contains a non-ASCII digit. An IPv4 part contains a leading 0. There are too many IPv4 parts.",
            .ipv4_in_ipv6_out_of_range_part => "An IPv6 address with IPv4 address syntax: an IPv4 part exceeds 255.",
            .ipv4_in_ipv6_too_few_parts => "An IPv6 address with IPv4 address syntax: an IPv4 address contains too few parts.",
            .invalid_url_unit => "A code point is found that is not a URL unit.",
            .special_scheme_missing_following_solidus => "The input’s scheme is not followed by \"//\".",
            .missing_scheme_non_relative_url => "The input is missing a scheme because it does not begin with an ASCII alpha, and either no base URL was provided or the base URL cannot be used as a base URL because it has an opaque path.",
            .invalid_reverse_solidus => "The URL has a special scheme and it uses U+005C (\\) instead of U+002F (/).",
            .invalid_credentials => "The input includes credentials.",
            .host_missing => "The input has a special scheme but does not contain a host.",
            .port_out_of_range => "The input’s port is too big.",
            .port_invalid => "The input’s port is invalid.",
            .file_invalid_windows_drive_letter => "The input is a relative-URL string that starts with a Windows drive letter and the base URL’s scheme is \"file\".",
            .file_invalid_windows_drive_letter_host => "A file: URL’s host is a Windows drive letter.",
        };
    }
};

/// "A validation error indicates a mismatch between input and valid input. User agents, especially conformance checkers, are encouraged to report them somewhere"
/// <https://url.spec.whatwg.org/#validation-error>
fn validationError(err: ValidationError, behavior: ValidationError.Behavior) error{Validation}!void {
    // TODO: Better validation errors
    if (behavior != .silent) std.debug.print("validation error: ({t}) {s}\n", .{ err, err.description() });
    if (behavior == .fail_parsing) return error.Validation;
}

// <https://url.spec.whatwg.org/#pointer>
const Pointer = struct {
    index: usize,
    input: []const u8,

    /// Since the index type is unsigned, -1 is represented by `std.math.maxInt(usize)`, and
    /// all increments and decrements use two's complement wrapping (i.e. `+%` and `-%` operators)
    pub const negative_one = std.math.maxInt(usize);

    pub fn init(input: []const u8) Pointer {
        return .{
            .index = 0,
            .input = input,
        };
    }

    /// "When a pointer is used, c references the code point the pointer points to as long as it does not point nowhere. When the pointer points to nowhere c cannot be used."
    /// Returns:
    /// - `null` when `pointer` points to "the EOF codepoint" (<https://url.spec.whatwg.org/#eof-code-point>)
    /// - ASCII character otherwise
    /// <https://url.spec.whatwg.org/#c>
    pub fn codepoint(pointer: Pointer) ?u8 {
        assert(!pointer.pointsNowhere());
        if (pointer.index >= pointer.input.len) return null;
        return pointer.input[pointer.index];
    }

    /// <https://url.spec.whatwg.org/#remaining>
    pub fn remaining(pointer: Pointer) []const u8 {
        assert(pointer.codepoint() != null);

        return pointer.input[pointer.index + 1 ..];
    }

    pub fn pointsNowhere(pointer: Pointer) bool {
        return pointer.index == negative_one;
    }

    pub fn inc(pointer: *Pointer) void {
        pointer.index +%= 1;
    }

    pub fn dec(pointer: *Pointer) void {
        pointer.index -%= 1;
    }
};

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

/// Various tracing functions
const trace = struct {
    pub const enable = true;

    pub fn step(src: std.builtin.SourceLocation, description: []const u8) void {
        if (!comptime enable) return;
        std.debug.print("trace(step): {d}: {s}\n", .{ src.line, description });
    }

    pub fn state(src: std.builtin.SourceLocation, machine_state: State) void {
        if (!comptime enable) return;
        std.debug.print("trace(state): {d}: {t}\n", .{ src.line, machine_state });
    }
};
