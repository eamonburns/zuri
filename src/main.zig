const std = @import("std");
const zuri = @import("zuri");
const Uri = zuri.Uri;

pub const uri_trace = true;

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer std.debug.assert(debug_allocator.deinit() == .ok);
    const gpa = debug_allocator.allocator();

    var args: std.process.ArgIterator = try .initWithAllocator(gpa);
    defer args.deinit();
    std.debug.assert(args.skip());

    const cmd = Command.parse(&args) catch |err| switch (err) {
        error.Help => exitHelp(0),
        error.MissingUri => {
            std.debug.print("error: <uri> is required\n", .{});
            exitHelp(1);
        },
    };

    const base = if (cmd.base) |b|
        try Uri.parse(gpa, b)
    else
        null;
    defer if (base) |b| b.deinit(gpa);

    const uri: Uri = try .parseExtended(gpa, cmd.uri, base, null);
    defer uri.deinit(gpa);
    std.debug.print("Uri: {f}\n", .{uri});
}

const Command = struct {
    uri: []const u8,
    base: ?[]const u8,

    pub const ParseError = error{ MissingUri, Help };

    pub fn parse(args: *std.process.ArgIterator) ParseError!Command {
        const eql = std.mem.eql;

        const uri: []const u8 = args.next() orelse return error.MissingUri;
        if (eql(u8, uri, "--help") or eql(u8, uri, "-h")) return error.Help;
        const base: ?[]const u8 = args.next();
        if (base) |b| if (eql(u8, b, "--help") or eql(u8, b, "-h")) {
            return error.Help;
        };

        return .{
            .uri = uri,
            .base = base,
        };
    }
};

fn exitHelp(status: u8) noreturn {
    std.debug.print(
        \\usage: zuri <uri> [base]
    , .{});

    std.process.exit(status);
}
