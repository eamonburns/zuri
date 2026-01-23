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

    const uri_str = args.next() orelse return error.UriRequired;

    const uri: Uri = try .parse(gpa, uri_str);
    std.debug.print("Uri: {f}\n", .{uri});
}
