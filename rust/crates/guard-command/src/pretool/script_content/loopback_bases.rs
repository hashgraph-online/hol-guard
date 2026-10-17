//! Loopback URLs an inline smoke test binds once and then fetches, as in
//! `const base = "http://127.0.0.1:3147"; await fetch(base + "/api")`.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

/// `const base = "http://127.0.0.1:3147"`: a name bound to a loopback URL
/// that names its port, which `fetch` may then take as its base. The
/// statement ends at `;`, `,`, the end of the source, or a line break that
/// starts a new statement: JavaScript continues an expression across a line
/// break followed by `+`, `.` or `?.`, which could move the host.
static LOOPBACK_BASE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["'`]http://(?:127\.0\.0\.1|localhost):[0-9]{1,5}(?:/[^"'`$\\]*)?["'`][ \t]*(?:[;,]|$|\n\s*(?:const|let|var|await|if|for|while|try|return|throw|console|fetch|function|async|import|export|class)\b)"#,
    )
    .unwrap()
});
/// The text before a name ends in a call of the global `fetch`.
static FETCH_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[^A-Za-z0-9_$.])fetch\s*\(\s*$").unwrap());
/// `fetch(base)`, `fetch(base, init)` or `fetch(base + "/path")`: the base
/// alone, or followed by a literal that starts a path, query or fragment, so
/// nothing appended can move the request to another host.
pub(super) static FETCH_BASE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^fetch\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:[),]|\+\s*["'`][/?#])"#).unwrap()
});
/// `function fetch(`, including a generator and any spacing before `fetch`.
static FETCH_DECLARATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bfunction\s*\*?\s*fetch\s*\(\s*$").unwrap());

/// `fetch(base)` calls the global. A declaration, generator, or method
/// shorthand (`function fetch(base)`, `function* fetch(base)`, `{fetch(base){`)
/// only names a parameter.
fn calls_fetch(masked: &str, start: usize) -> bool {
    let prefix = &masked[..start];
    if !FETCH_CALL.is_match(prefix) || FETCH_DECLARATION.is_match(prefix) {
        return false;
    }
    // `fetch(base){` is a method's parameter list, not a call.
    let rest = &masked[start..];
    let after = rest.find(')').map(|close| rest[close + 1..].trim_start());
    !after.is_some_and(|tail| tail.starts_with('{'))
}

/// Names `const`-bound to a loopback URL with a port ([`LOOPBACK_BASE`]) and
/// read nowhere else but as the first argument of `fetch`, so no other code
/// can rebind, shadow or pass them on. The URL scan grants the port.
pub(super) fn loopback_bases<'a>(code: &'a str, masked: &str) -> BTreeSet<&'a str> {
    let mut bases = BTreeSet::new();
    for binding in LOOPBACK_BASE.captures_iter(code) {
        let Some(name) = binding.get(1) else {
            continue;
        };
        let Ok(word) = Regex::new(&format!(r"\b{}\b", regex::escape(name.as_str()))) else {
            continue;
        };
        let fetched_only = masked
            .as_bytes()
            .get(name.start())
            .is_some_and(|byte| *byte != b' ')
            && word
                .find_iter(masked)
                .all(|found| found.start() == name.start() || calls_fetch(masked, found.start()));
        if fetched_only {
            bases.insert(name.as_str());
        }
    }
    bases
}
