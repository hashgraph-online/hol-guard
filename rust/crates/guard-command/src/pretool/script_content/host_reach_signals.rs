//! Programs that send a signal to another process: `os.kill`,
//! `signal.pthread_kill` and their siblings, reached by name, through an
//! `import ... as` alias, or through another module's attribute.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

/// `from os import kill` and its siblings, including the parenthesized form
/// spread over several lines, which make the call bare.
static SIGNAL_IMPORT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\bfrom\s+(?:os|signal)\s+import\s+",
        r"(?:\([^)]*\b(?:kill|killpg|pthread_kill)\b[^)]*\)",
        r"|[\w, \t\\]*\b(?:kill|killpg|pthread_kill)\b)",
    ))
    .unwrap()
});

/// `from os import *`, after which a bare `kill(` is the signal call.
static SIGNAL_STAR_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfrom\s+(?:os|signal)\s+import\s+\*").unwrap());

static BARE_SIGNAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[^.\w])(?:kill|killpg|pthread_kill)\s*\(").unwrap());

/// A signal call, or a reference to one kept for later (`k = os.kill`), on
/// a receiver; the receiver is checked against `os`, `signal`, `posix`, `nt`
/// and the names they are imported as.
static SIGNAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\w+)\s*\.\s*(?:kill|killpg|pthread_kill)\b").unwrap());

/// `os` or `signal` reached as an attribute of another module
/// (`subprocess.os`, `__import__('subprocess').os`) or imported from one
/// under a new name (`from subprocess import os as p`). The name it is
/// bound to is not one the signal screen knows, so any signal method call
/// then counts.
static SIGNAL_MODULE_HANDLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?:(?:\b(?P<owner>\w+)|[)\]])\s*\.\s*(?:os|posix|nt|signal|_signal)\b",
        r"|\bimport\b[^\n;#]*\b(?:os|posix|nt|signal|_signal)\s+as\b)",
    ))
    .unwrap()
});

static ANY_SIGNAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.\s*(?:kill|killpg|pthread_kill)\b").unwrap());

/// The body of an `import` statement, to find `import os as proc`.
static IMPORT_STATEMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)(?:^|[;:])[ \t]*import[ \t]+([^\n;#]+)").unwrap());

/// Names the signal modules are reachable under: themselves and their
/// `import ... as` aliases.
fn signal_receivers(code: &str) -> BTreeSet<&str> {
    let mut names = BTreeSet::from(["os", "signal", "_signal", "posix", "nt"]);
    for statement in IMPORT_STATEMENT.captures_iter(code) {
        let body = statement.get(1).map_or("", |body| body.as_str());
        for item in body.split(',') {
            let parts: Vec<&str> = item.split_whitespace().collect();
            if let [module, "as", alias] = parts.as_slice() {
                if matches!(*module, "os" | "signal" | "_signal" | "posix" | "nt") {
                    names.insert(alias);
                }
            }
        }
    }
    names
}

pub(super) fn signals_processes(code: &str) -> bool {
    if SIGNAL_IMPORT.is_match(code)
        || (SIGNAL_STAR_IMPORT.is_match(code) && BARE_SIGNAL_CALL.is_match(code))
    {
        return true;
    }
    let handle = SIGNAL_MODULE_HANDLE.captures_iter(code).any(|found| {
        found.name("owner").is_none_or(|owner| {
            !matches!(owner.as_str(), "os" | "posix" | "nt" | "signal" | "_signal")
        })
    });
    if handle && ANY_SIGNAL_CALL.is_match(code) {
        return true;
    }
    let receivers = signal_receivers(code);
    SIGNAL_CALL
        .captures_iter(code)
        .any(|call| receivers.contains(&call[1]))
}
