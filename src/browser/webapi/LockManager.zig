// Copyright (C) 2023-2026 Lightpanda (Selecy SAS)
//
// Francis Bouvier <francis@lightpanda.io>
// Pierre Tachoire <pierre@lightpanda.io>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

const std = @import("std");
const js = @import("../js/js.zig");
const AbortSignal = @import("AbortSignal.zig");
const DOMException = @import("DOMException.zig");

const LockManager = @This();
_pad: bool = false,

pub fn registerTypes() []const type {
    return &.{ LockManager, Lock };
}

const Mode = enum {
    exclusive,
    shared,
    pub const js_enum_from_string = true;
};

const Options = struct {
    ifAvailable: bool = false,
    mode: Mode = .exclusive,
    signal: ?*AbortSignal = null,
    steal: bool = false,
};

fn request(_: *LockManager, name: []const u8, options_or_callback: js.Value, callback: ?js.Function.Global, exec: *const js.Execution) !js.Promise {
    const local = exec.js.local.?;
    const resolver = local.createPromiseResolver();
    const is_callback = options_or_callback.isFunction();
    const cb = if (is_callback) try options_or_callback.toZig(js.Function.Global) else callback orelse {
        resolver.rejectError("LockManager.request", .{ .type_error = "A lock callback is required" });
        return resolver.promise();
    };
    errdefer cb.release();
    const options: Options = if (is_callback) .{} else try options_or_callback.toZig(Options);
    if (exec.origin() == null or std.mem.startsWith(u8, name, "-") or
        (options.steal and (options.ifAvailable or options.mode != .exclusive)) or
        (options.signal != null and (options.steal or options.ifAvailable))) {
        cb.release();
        resolver.rejectError("LockManager.request", .{ .dom_exception = .{ .err = if (exec.origin() == null) error.SecurityError else error.NotSupportedError } });
        return resolver.promise();
    }
    if (options.signal) |signal| {
        if (signal.getAborted()) {
            const reason = try AbortSignal.reasonJsValue(signal._reason, local);
            cb.release();
            try resolver.rejectValue(reason);
            return resolver.promise();
        }
    }
    const req = try exec.arena.create(Request);
    const global_resolver = try resolver.persist();
    errdefer global_resolver.release();
    req.* = .{
        .exec = exec.*,
        .name = try exec.dupeString(name),
        .origin = try exec.dupeString(exec.origin().?),
        .mode = options.mode,
        .if_available = options.ifAvailable,
        .signal = options.signal,
        .callback = cb,
        .resolver = global_resolver,
    };
    const requests = &exec.session.web_locks;
    if (options.steal) {
        // A stolen holder's returned request promise rejects in its own realm.
        // Pending requests stay queued behind the new exclusive request.
        for (requests.items) |other| {
            if (other.phase == .held and req.sameResource(other)) other.preempted = true;
        }
        try requests.insert(exec.session.arena.allocator(), 0, req);
    } else {
        try requests.append(exec.session.arena.allocator(), req);
    }
    errdefer req.remove();
    try exec.js.scheduler.add(req, Request.run, 0, .{
        .name = "LockManager.request",
        .blocks_done = false,
        .finalizer = Request.cancelled,
    });
    return resolver.promise();
}

fn query(_: *LockManager, exec: *const js.Execution) !js.Promise {
    const Info = struct { name: []const u8, mode: []const u8, clientId: []const u8 };
    var held: std.ArrayList(Info) = .empty;
    var pending: std.ArrayList(Info) = .empty;
    if (exec.origin()) |origin| {
        for (exec.session.web_locks.items) |req| {
            if (req.preempted or !std.mem.eql(u8, req.origin, origin)) continue;
            const info: Info = .{
                .name = req.name,
                .mode = @tagName(req.mode),
                .clientId = try std.fmt.allocPrint(exec.local_arena, "client-{d}", .{req.exec.frameId()}),
            };
            switch (req.phase) {
                .held => try held.append(exec.local_arena, info),
                .waiting => try pending.append(exec.local_arena, info),
                .unavailable, .done => {},
            }
        }
    }
    return exec.js.local.?.resolvePromise(.{ .held = held.items, .pending = pending.items });
}

pub const Request = struct {
    exec: js.Execution,
    name: []const u8,
    origin: []const u8,
    mode: Mode,
    if_available: bool,
    signal: ?*AbortSignal,
    callback: ?js.Function.Global,
    resolver: ?js.PromiseResolver.Global,
    waiting: ?js.Promise.Global = null,
    phase: enum { waiting, held, unavailable, done } = .waiting,
    preempted: bool = false,

    fn sameResource(self: *const Request, other: *const Request) bool {
        return std.mem.eql(u8, self.name, other.name) and std.mem.eql(u8, self.origin, other.origin);
    }

    fn remove(self: *Request) void {
        const requests = &self.exec.session.web_locks;
        for (requests.items, 0..) |other, i| {
            if (other == self) {
                _ = requests.orderedRemove(i);
                break;
            }
        }
    }

    fn cleanup(self: *Request) void {
        if (self.phase == .done) return;
        self.phase = .done;
        self.remove();
        if (self.callback) |cb| cb.release();
        if (self.resolver) |resolver| resolver.release();
        if (self.waiting) |waiting| waiting.release();
        self.callback = null;
        self.resolver = null;
        self.waiting = null;
    }

    fn cancelled(ctx: *anyopaque) void {
        const self: *Request = @ptrCast(@alignCast(ctx));
        // Destroying a document/worker releases its locks before its arena dies.
        self.cleanup();
    }

    fn grantable(self: *Request) bool {
        var before = true;
        for (self.exec.session.web_locks.items) |other| {
            if (other == self) { before = false; continue; }
            if (other.preempted or !self.sameResource(other)) continue;
            if (other.phase == .held and (self.mode == .exclusive or other.mode == .exclusive)) return false;
            if (before and other.phase == .waiting and (self.mode == .exclusive or other.mode == .exclusive)) return false;
        }
        return true;
    }

    fn finish(self: *Request, local: *const js.Local, value: js.Value, rejected: bool) !void {
        const resolver = self.resolver.?.local(local);
        // Release the lock before promise reactions can request another lock,
        // close their worker, or navigate the document.
        self.cleanup();
        if (rejected) {
            try resolver.rejectValue(value);
        } else {
            resolver.resolve("LockManager.request", value);
        }
    }

    fn run(ctx: *anyopaque) !?u32 {
        const self: *Request = @ptrCast(@alignCast(ctx));
        if (self.phase == .done) return null;
        errdefer self.cleanup();
        var ls: js.Local.Scope = undefined;
        self.exec.js.localScope(&ls);
        defer ls.deinit();
        const local = &ls.local;
        if (self.preempted) {
            try self.finish(local, try local.zigValueToJs(DOMException.fromError(error.AbortError).?, .{}), true);
            return null;
        }
        if (self.phase == .waiting) {
            if (self.signal) |signal| {
                if (signal.getAborted()) {
                    try self.finish(local, try AbortSignal.reasonJsValue(signal._reason, local), true);
                    return null;
                }
            }
            const available = self.grantable();
            if (!available and !self.if_available) return 10;
            self.phase = if (available) .held else .unavailable;
            const lock: ?*Lock = if (available) try self.exec._factory.create(Lock{ ._name = self.name, ._mode = self.mode }) else null;
            var cb = self.callback.?.local(local);
            var caught: js.TryCatch = undefined;
            caught.init(local);
            defer caught.deinit();
            const result = cb.callRethrow(js.Value, .{lock}) catch |err| {
                const exception = caught.exceptionValue() orelse return err;
                try self.finish(local, exception, true);
                return null;
            };
            // close() may reset the scheduler from inside the callback.
            if (self.phase == .done) return null;
            const waiting_resolver = local.createPromiseResolver();
            const waiting = waiting_resolver.promise();
            waiting.markAsHandled();
            self.waiting = try waiting.persist();
            waiting_resolver.resolve("LockManager.callback", result);
            if (self.phase == .done) return null;
        }
        const waiting = self.waiting.?.local(local);
        switch (waiting.state()) {
            .pending => return 50,
            .fulfilled => try self.finish(local, waiting.result(), false),
            .rejected => try self.finish(local, waiting.result(), true),
        }
        return null;
    }
};

const Lock = struct {
    _name: []const u8,
    _mode: Mode,
    fn getName(self: *const Lock) []const u8 { return self._name; }
    fn getMode(self: *const Lock) []const u8 { return @tagName(self._mode); }
    pub const JsApi = struct {
        pub const bridge = js.Bridge(Lock);
        pub const Meta = struct {
            pub const name = "Lock";
            pub const prototype_chain = bridge.prototypeChain();
            pub var class_id: bridge.ClassId = undefined;
        };
        pub const name = bridge.accessor(Lock.getName, null, .{});
        pub const mode = bridge.accessor(Lock.getMode, null, .{});
    };
};

pub const JsApi = struct {
    pub const bridge = js.Bridge(LockManager);
    pub const Meta = struct {
        pub const name = "LockManager";
        pub const prototype_chain = bridge.prototypeChain();
        pub var class_id: bridge.ClassId = undefined;
    };
    pub const request = bridge.function(LockManager.request, .{});
    pub const query = bridge.function(LockManager.query, .{});
};
