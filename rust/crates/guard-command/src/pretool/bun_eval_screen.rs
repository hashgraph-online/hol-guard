//! Lexical screen for a `bun -e/-p <program>` routed to the read-only
//! evaluation boundary.
//!
//! The sandbox is the enforcement boundary; this screen only keeps programs
//! that visibly reach for more than reading workspace files on the ordinary
//! review path. It is deliberately coarse: every identifier in the text,
//! including those in strings and comments, is checked, and any doubt fails
//! the screen. A failed screen leaves the command exactly as reviewed before.

use crate::sfrs_node_redaction::node_script_contains_sensitive_runtime_behavior;

const MAX_PROGRAM_BYTES: usize = 4096;

/// Names that reach the network, processes, the environment, code
/// generation, the global object, or a file write the destructive-call scan
/// does not list.
const BLOCKED_NAMES: &[&str] = &[
    "$",
    "AsyncFunction",
    "Deno",
    "EventSource",
    "Function",
    "GeneratorFunction",
    "Proxy",
    "Reflect",
    "SharedWorker",
    "WebAssembly",
    "WebSocket",
    "Worker",
    "XMLHttpRequest",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
    "__proto__",
    "_linkedBinding",
    "binding",
    "captureStackTrace",
    "child_process",
    "cluster",
    "constructor",
    "cp",
    "cpSync",
    "createWriteStream",
    "defineProperties",
    "defineProperty",
    "dgram",
    "dlopen",
    "dns",
    "env",
    "eval",
    "exec",
    "execFile",
    "execFileSync",
    "execSync",
    "fchmod",
    "fchmodSync",
    "fchown",
    "fchownSync",
    "fdatasync",
    "fdatasyncSync",
    "fetch",
    "ffi",
    "fork",
    "fsync",
    "fsyncSync",
    "ftruncate",
    "ftruncateSync",
    "futimes",
    "futimesSync",
    "getOwnPropertyDescriptor",
    "getOwnPropertyDescriptors",
    "getPrototypeOf",
    "global",
    "globalThis",
    "http",
    "http2",
    "https",
    "import",
    "inspector",
    "kill",
    "lchmod",
    "lchmodSync",
    "lchown",
    "lchownSync",
    "link",
    "linkSync",
    "lutimes",
    "lutimesSync",
    "mainModule",
    "mkdtemp",
    "mkdtempSync",
    "module",
    "net",
    "open",
    "openSync",
    "prepareStackTrace",
    "prototype",
    "rmdir",
    "rmdirSync",
    "self",
    "setImmediate",
    "setInterval",
    "setPrototypeOf",
    "setTimeout",
    "spawn",
    "spawnSync",
    "sqlite",
    "symlink",
    "symlinkSync",
    "this",
    "tls",
    "utimes",
    "utimesSync",
    "vm",
    "window",
    "worker_threads",
    "write",
    "writeSync",
    "writev",
    "writevSync",
];

/// Text that hides an identifier or names process state outside the program.
const BLOCKED_TEXT: &[&str] = &["\\u", "\\x", "$`", "/proc", "/dev/", "environ"];

/// Plain reads of the runtime's own identity.
const BUN_MEMBERS: &[&str] = &["revision", "version"];

const PROCESS_MEMBERS: &[&str] = &[
    "arch",
    "argv",
    "cwd",
    "exit",
    "exitCode",
    "hrtime",
    "memoryUsage",
    "pid",
    "platform",
    "stderr",
    "stdout",
    "uptime",
    "version",
    "versions",
];

const REQUIRE_MODULES: &[&str] = &[
    "fs",
    "fs/promises",
    "node:fs",
    "node:fs/promises",
    "node:path",
    "path",
];

/// Whether `program` shows nothing beyond reading files and printing.
pub(super) fn reads_only(program: &str) -> bool {
    !program.trim().is_empty()
        && program.len() <= MAX_PROGRAM_BYTES
        && !BLOCKED_TEXT.iter().any(|text| program.contains(text))
        && identifiers_allowed(program)
        && computed_members_allowed(program)
        && !node_script_contains_sensitive_runtime_behavior(program)
}

fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn identifiers_allowed(program: &str) -> bool {
    let bytes = program.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !identifier_byte(bytes[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && identifier_byte(bytes[index]) {
            index += 1;
        }
        if !bytes[start].is_ascii_digit() && !identifier_allowed(program, start, index) {
            return false;
        }
    }
    true
}

fn identifier_allowed(program: &str, start: usize, end: usize) -> bool {
    let name = &program[start..end];
    let after = &program[end..];
    match name {
        // A template interpolation, not Bun's shell.
        "$" => after.starts_with('{'),
        // Printing through the inherited stream.
        "write" => {
            let before = &program[..start];
            before.ends_with("stdout.") || before.ends_with("stderr.")
        }
        "Bun" => member(after).is_some_and(|member| BUN_MEMBERS.contains(&member)),
        "process" => member(after).is_some_and(|member| PROCESS_MEMBERS.contains(&member)),
        "require" => required_module(after).is_some_and(|name| REQUIRE_MODULES.contains(&name)),
        // Any mention of a destructive fs call fails, so a renamed
        // destructuring such as `{ rmSync: r }` cannot slip past the call scan.
        name => {
            !BLOCKED_NAMES.contains(&name)
                && !crate::sfrs_patterns::DESTRUCTIVE_NODE_INLINE_CALLS.contains(&name)
        }
    }
}

/// `.name` or `?.name` directly after an identifier.
fn member(after: &str) -> Option<&str> {
    let rest = after.trim_start();
    let rest = rest.strip_prefix('?').unwrap_or(rest);
    let rest = rest.strip_prefix('.')?.trim_start();
    let end = rest
        .bytes()
        .position(|byte| !identifier_byte(byte))
        .unwrap_or(rest.len());
    if end == 0 {
        None
    } else {
        Some(&rest[..end])
    }
}

/// The module of `('name')` or `("name")` directly after `require`.
fn required_module(after: &str) -> Option<&str> {
    let rest = after.trim_start().strip_prefix('(')?.trim_start();
    let quote = rest
        .chars()
        .next()
        .filter(|quote| matches!(quote, '\'' | '"'))?;
    let rest = &rest[1..];
    let end = rest.find(quote)?;
    let (name, tail) = (&rest[..end], &rest[end + 1..]);
    tail.trim_start().starts_with(')').then_some(name)
}

/// Every `[...]` holds only literals, so no member name can be computed.
fn computed_members_allowed(program: &str) -> bool {
    let mut rest = program;
    while let Some(open) = rest.find('[') {
        let tail = &rest[open + 1..];
        let Some(close) = tail.find(']') else {
            return false;
        };
        if !tail[..close].split(',').all(literal) {
            return false;
        }
        rest = &tail[close + 1..];
    }
    true
}

fn literal(item: &str) -> bool {
    let item = item.trim();
    if item.is_empty() || item.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    let bytes = item.as_bytes();
    bytes.len() >= 2
        && matches!(bytes[0], b'\'' | b'"')
        && bytes[bytes.len() - 1] == bytes[0]
        && !item[1..item.len() - 1].contains(['\'', '"', '\\', '`', '+'])
}

#[cfg(test)]
#[path = "bun_eval_screen_tests.rs"]
mod tests;
