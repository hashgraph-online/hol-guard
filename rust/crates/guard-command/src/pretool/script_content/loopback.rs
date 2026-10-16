//! Inline Node source whose only network use is loopback HTTP on literal
//! ports: a server listening on `127.0.0.1` or `localhost`, and `fetch`
//! calls to a loopback URL, as agents write to smoke-test a page they built.
//!
//! Such a program runs in the workspace sandbox, which grants exactly these
//! loopback ports and still withholds every other address. The sandbox, not
//! this scan, bounds the program: the scan names the ports to grant and
//! predicts that nothing else is needed. Any other network client, a dynamic
//! host or port, an administrative port or a credential store keeps the
//! review.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

use super::launch::{launched_program, Program};
use super::{code_lines, python_network, Language, CREDENTIAL_STORE, NODE_NETWORK};

/// Loopback services this grant must never reach: container and cluster
/// control planes, service meshes, debuggers, Guard's own approval center,
/// message brokers, and data stores that accept local clients without
/// credentials.
///
/// The sandbox opens a granted port to the whole process tree as raw outbound
/// TCP, not as HTTP, so the question each port answers is "could something
/// under this command speak that service's protocol", not "could an HTTP
/// request drive it". A smoke test fetching a page it just built reaches none
/// of them.
const ADMIN_PORTS: &[u16] = &[
    1433, 1521, 2019, 2181, 2375, 2376, 2379, 2380, 3306, 4001, 4243, 4646, 4781, 5432, 5433, 5672,
    5984, 6379, 6380, 6443, 7474, 7687, 8001, 8086, 8123, 8200, 8500, 9042, 9092, 9200, 9222, 9229,
    9300, 11211, 15000, 15672, 26257, 33060,
];
/// Services whose components bind a whole block of loopback ports.
const ADMIN_PORT_RANGES: &[std::ops::RangeInclusive<u16>] = &[10248..=10256, 27017..=27019];

/// Whether the workspace sandbox may open `port` to the contained tree: a
/// conventional dev-server port ([`crate::pretool::loopback_ports`]) that
/// none of these services and no Guard daemon under `home_dir` may answer
/// on.
///
/// Ports below 1024 are refused as a class: every one of them belongs to a
/// registered service, and a dev server an agent starts to smoke-test its own
/// page binds none of them without privilege it does not have here.
fn grantable(port: u16, home_dir: Option<&str>) -> bool {
    port >= 1024
        && !ADMIN_PORT_RANGES.iter().any(|range| range.contains(&port))
        && crate::pretool::loopback_ports::dev_server_port(port, ADMIN_PORTS, home_dir)
}

/// HTTP module members that open no connection of their own.
const HTTP_MEMBERS: &[&str] = &["createServer", "STATUS_CODES", "METHODS"];

static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z][A-Za-z0-9+.\-]*://").unwrap());
/// A loopback URL whose authority ends at its literal port.
static LOOPBACK_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^http://(?:127\.0\.0\.1|localhost):([0-9]{1,5})(?:[/?#"'`]|$)"#).unwrap()
});
static FETCH_LITERAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^fetch\s*\(\s*["'`]http://(?:127\.0\.0\.1|localhost):[0-9]{1,5}[/?#"'`]"#)
        .unwrap()
});
/// Code built at run time. A direct `eval(` or `Function(` is not the only
/// shape: `(0, eval)(...)`, `eval?.(...)`, `const F = Function`, and
/// `[].constructor` reach the same constructors. `require` or `import` of a
/// name that is not a literal is the same problem. Matched on the
/// string-masked source, so a literal specifier still reads as an opening quote.
static DYNAMIC_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\beval\b|\bFunction\b|\.\s*constructor\b|\b(?:require|import)\s*\(\s*[^"'`\s]|\bprocess\s*\.\s*binding\b"#,
    )
    .unwrap()
});
static VM_MODULE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'`](?:node:)?vm["'`]"#).unwrap());
static LISTEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.\s*listen\s*\(").unwrap());
static LOOPBACK_LISTEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\.\s*listen\s*\(\s*([0-9]{1,5})\s*,\s*(?:"(?:127\.0\.0\.1|localhost)"|'(?:127\.0\.0\.1|localhost)')\s*[,)]"#,
    )
    .unwrap()
});
static MODULE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["'](?:node:)?([^"']+)["']"#).unwrap());
/// `const http = require("node:http")` or `import http from "node:http"`.
static HTTP_BINDING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b(\w+)\s*=\s*require\s*\(\s*["'](?:node:)?http["']\s*\)|\bimport\s+(?:\*\s*as\s+)?(\w+)\s+from\s*["'](?:node:)?http["']"#,
    )
    .unwrap()
});
/// `const { createServer } = require("node:http")` and its `import` form.
static HTTP_NAMED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\{([^{}]*)\}\s*=\s*require\s*\(\s*["'](?:node:)?http["']\s*\)|\bimport\s*\{([^{}]*)\}\s*from\s*["'](?:node:)?http["']"#,
    )
    .unwrap()
});
static HTTP_MEMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*\.\s*(\w+)").unwrap());

/// The loopback ports a Node program's source `code` (its comments already
/// dropped) listens and fetches on, when that is all of its network use;
/// `None` for anything else.
pub(super) fn node_loopback_ports(code: &str, home_dir: Option<&str>) -> Option<BTreeSet<u16>> {
    // A template expansion is code the string mask below would hide.
    if code.contains("${") || CREDENTIAL_STORE.is_match(code) {
        return None;
    }
    let masked = mask_strings(code)?;
    if DYNAMIC_CODE.is_match(&masked) || VM_MODULE.is_match(code) {
        return None;
    }
    let in_code = |at: usize| masked.as_bytes().get(at).is_some_and(|byte| *byte != b' ');
    let mut http_imports = 0usize;
    for found in NODE_NETWORK.find_iter(code) {
        // A network API spelled inside a string is code something may
        // evaluate, which this scan cannot follow.
        if !in_code(found.start()) {
            return None;
        }
        let text = found.as_str();
        if text.starts_with("fetch") {
            if !FETCH_LITERAL.is_match(&code[found.start()..]) {
                return None;
            }
            continue;
        }
        let module = MODULE.captures(text)?;
        if &module[1] != "http" {
            return None;
        }
        http_imports += 1;
    }
    let mut bindings = Vec::new();
    let mut recognized = 0usize;
    for capture in HTTP_BINDING.captures_iter(code) {
        let name = capture.get(1).or_else(|| capture.get(2))?;
        if in_code(name.start()) {
            bindings.push(name);
            recognized += 1;
        }
    }
    for capture in HTTP_NAMED.captures_iter(code) {
        let names = capture.get(1).or_else(|| capture.get(2))?;
        if !in_code(names.start().saturating_sub(1)) {
            continue;
        }
        let mut imported = names.as_str().split(',').filter_map(|name| {
            name.split([':', ' ', '\t', '\n'])
                .find(|part| !part.is_empty() && *part != "as")
        });
        if !imported.all(|name| HTTP_MEMBERS.contains(&name)) {
            return None;
        }
        recognized += 1;
    }
    // An import the forms above do not name, such as `require("http").get`.
    if recognized != http_imports {
        return None;
    }
    for binding in bindings {
        if !members_only(&masked, binding.as_str(), binding.start()) {
            return None;
        }
    }
    let mut ports = BTreeSet::new();
    for found in URL.find_iter(code) {
        let port = LOOPBACK_URL.captures(&code[found.start()..])?;
        ports.insert(port[1].parse::<u16>().ok()?);
    }
    for found in LISTEN.find_iter(&masked) {
        let port = LOOPBACK_LISTEN.captures(&code[found.start()..])?;
        ports.insert(port[1].parse::<u16>().ok()?);
    }
    ports
        .iter()
        .all(|port| grantable(*port, home_dir))
        .then_some(ports)
}

/// Whether every use of the HTTP module bound to `name`, besides its
/// declaration at `declared`, reads a member that opens no connection.
fn members_only(masked: &str, name: &str, declared: usize) -> bool {
    let Ok(word) = Regex::new(&format!(r"\b{}\b", regex::escape(name))) else {
        return false;
    };
    for found in word.find_iter(masked) {
        let only_member = found.start() == declared
            // `config.http` is another object's property.
            || masked[..found.start()].trim_end().ends_with('.')
            || HTTP_MEMBER
                .captures(&masked[found.end()..])
                .is_some_and(|member| HTTP_MEMBERS.contains(&&member[1]));
        if !only_member {
            return false;
        }
    }
    true
}

/// `code` with the contents of each string literal blanked, byte for byte,
/// so a name inside a string is not read as code. `None` when a literal is
/// left open.
fn mask_strings(code: &str) -> Option<String> {
    let mut bytes = code.as_bytes().to_vec();
    let (mut quote, mut escaped) = (None, false);
    for byte in &mut bytes {
        match quote {
            Some(_) if escaped => {
                escaped = false;
                *byte = b' ';
            }
            Some(_) if *byte == b'\\' => {
                escaped = true;
                *byte = b' ';
            }
            Some(open) if *byte == open => quote = None,
            Some(_) => *byte = b' ',
            None if matches!(*byte, b'"' | b'\'' | b'`') => quote = Some(*byte),
            None => {}
        }
    }
    if quote.is_some() {
        return None;
    }
    // Only whole characters inside literals were blanked.
    String::from_utf8(bytes).ok()
}

/// The loopback ports inline Node source in the program `command` runs
/// (`/bin/sh -c <text>`) serves and fetches on, for the workspace sandbox to
/// grant. Empty when any inline program uses other network, so the sandbox
/// then withholds the network whole, as it did before.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn inline_loopback_ports(command: &[String], home_dir: Option<&str>) -> Vec<u16> {
    let [shell, flag, text] = command else {
        return Vec::new();
    };
    if shell != "/bin/sh" || flag != "-c" {
        return Vec::new();
    }
    let Ok(model) = crate::parse_command(&crate::CommandModelRequestV1 {
        command: text.clone(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    }) else {
        return Vec::new();
    };
    if model.confidence != "exact" {
        return Vec::new();
    }
    let mut ports = BTreeSet::new();
    for segment in &model.segments {
        let Some((language, Program::Inline(source), false)) = launched_program(segment) else {
            continue;
        };
        let code = code_lines(language, source);
        let found = match language {
            Language::Python if python_network(&code) => None,
            Language::Python => continue,
            Language::Node if NODE_NETWORK.is_match(&code) => node_loopback_ports(&code, home_dir),
            Language::Node => continue,
        };
        match found {
            Some(found) => ports.extend(found),
            None => return Vec::new(),
        }
    }
    ports.into_iter().collect()
}

/// The ports a launched program's sources earn: its inline Node source
/// when it is loopback-only and no local module it imports uses the
/// network or names a credential store.
pub(super) fn program_ports(sources: &[String], home_dir: Option<&str>) -> Option<BTreeSet<u16>> {
    let (first, imports) = sources.split_first()?;
    let clean = imports.iter().all(|source| {
        let code = code_lines(Language::Node, source);
        !NODE_NETWORK.is_match(&code) && !CREDENTIAL_STORE.is_match(&code)
    });
    clean
        .then(|| node_loopback_ports(&code_lines(Language::Node, first), home_dir))
        .flatten()
}

#[cfg(test)]
#[path = "loopback_tests.rs"]
mod tests;
