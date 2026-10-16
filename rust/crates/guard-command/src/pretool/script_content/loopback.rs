//! Node source whose only network use is loopback HTTP on literal ports: a
//! server listening on a literal port with no host or a loopback or wildcard
//! one, and `fetch` calls to a loopback URL, as agents write to smoke-test a
//! page they built. The source is inline (`node -e`) or a script file in the
//! working directory whose local imports were all read.
//!
//! Such a program runs in the workspace sandbox, which grants exactly these
//! ports and still withholds every other one and every remote host. The
//! sandbox, not this scan, bounds the program: the scan names the ports to
//! grant and predicts that nothing else is needed. Any other network client,
//! a dynamic host or port, an administrative port or a credential store keeps
//! the review.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::launch::{launched_program, Program};
use super::loopback_bases::{loopback_bases, FETCH_BASE};
use super::{
    code_lines, python_network, Entry, Language, PathContext, CREDENTIAL_STORE, NODE_NETWORK,
};

/// Loopback services this grant must never reach: container and cluster
/// control planes, service meshes, debuggers, Guard's own approval center,
/// message brokers, data stores that accept local clients without
/// credentials, local proxies that would carry traffic off this host,
/// browser and device automation drivers, remote desktops, and local model
/// and notebook servers.
///
/// The sandbox opens a granted port to the whole process tree as raw outbound
/// TCP, not as HTTP, so the question each port answers is "could something
/// under this command speak that service's protocol", not "could an HTTP
/// request drive it". A smoke test fetching a page it just built reaches none
/// of them.
const ADMIN_PORTS: &[u16] = &[
    1080, 1086, 1087, 1433, 1521, 2019, 2049, 2181, 2375, 2376, 2379, 2380, 3128, 3306, 3389, 4001,
    4243, 4444, 4646, 4723, 4781, 5037, 5432, 5433, 5555, 5672, 5984, 6379, 6380, 6443, 6463, 7474,
    7687, 7890, 7891, 7897, 8001, 8086, 8118, 8123, 8200, 8384, 8500, 8888, 8889, 9000, 9001, 9042,
    9050, 9090, 9092, 9150, 9200, 9222, 9229, 9300, 9515, 10000, 10808, 10809, 11211, 11434, 15000,
    15672, 26257, 33060,
];
/// Services whose components bind a whole block of loopback ports: VNC and
/// X11 displays, the kubelet, and MongoDB.
const ADMIN_PORT_RANGES: &[std::ops::RangeInclusive<u16>] =
    &[5900..=5910, 6000..=6063, 10248..=10256, 27017..=27019];

/// Whether the workspace sandbox may open `port` to the contained tree: a
/// conventional dev-server port ([`crate::pretool::loopback_ports`]), or one
/// the agent chose for its own server while Guard's daemon state records
/// another, that none of these services and no Guard daemon under
/// `home_dir` may answer on.
///
/// Ports below 1024 are refused as a class: every one of them belongs to a
/// registered service, and a dev server an agent starts to smoke-test its own
/// page binds none of them without privilege it does not have here.
fn grantable(port: u16, home_dir: Option<&str>) -> bool {
    port >= 1024
        && !ADMIN_PORT_RANGES.iter().any(|range| range.contains(&port))
        && (crate::pretool::loopback_ports::dev_server_port(port, ADMIN_PORTS, home_dir)
            || crate::pretool::loopback_ports::chosen_server_port(port, ADMIN_PORTS, home_dir))
}

/// HTTP module members that open no connection of their own.
const HTTP_MEMBERS: &[&str] = &["createServer", "STATUS_CODES", "METHODS"];

static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z][A-Za-z0-9+.\-]*://").unwrap());
/// A loopback URL whose authority ends at its literal port, or names no port,
/// as the base `new URL(request.url, "http://localhost")` parses against.
/// Only a named port is granted; `fetch` must name one.
static LOOPBACK_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^http://(?:127\.0\.0\.1|localhost)(?::([0-9]{1,5}))?(?:[/?#"'`]|$)"#).unwrap()
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
/// What may follow a `.listen(` port argument: the end of the call, a
/// callback, or a loopback or wildcard host literal. The port itself is read
/// by `port_expressions::literal_port` or names a bound port. A callback
/// named by a bare identifier is checked against [`STRING_BINDING`], so a
/// host held in a variable keeps the review.
///
/// The host is not what keeps the server local. On macOS a Seatbelt
/// `localhost` inbound rule matches every local address, so the grant bounds
/// the port, not the interface; outbound stays limited to this host. On
/// Linux the sandbox has a private loopback.
static LISTEN_REST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"^\s*(?:\)|,\s*(?:(?:"(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::)"|'(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::)')\s*[,)]|function\b|async\b|\(|([A-Za-z_$][A-Za-z0-9_$]*)\s*[,)]))"#,
    )
    .unwrap()
});
/// `const HOST = "..."`: a name bound to a string, which as the second
/// `listen` argument would be a host, not a callback.
static STRING_BINDING: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*["'`]"#).unwrap()
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
/// `require("node:http").createServer`, read straight off the import.
static REQUIRED_SERVER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*\)\s*\.\s*createServer\b").unwrap());

/// The loopback ports a Node program's source `code` (its comments already
/// dropped) listens and fetches on, when that is all of its network use;
/// `None` for anything else.
pub(super) fn node_loopback_ports(code: &str, home_dir: Option<&str>) -> Option<BTreeSet<u16>> {
    let constants = mask_strings(code)
        .map(|masked| port_expressions::port_constants(&masked))
        .unwrap_or_default();
    // `${PORT}` or `${process.env.PORT ?? 3000}` reads as its literal port.
    let expanded = port_expressions::expand_templates(code, &constants);
    let code: &str = &expanded;
    // Any other template expansion is code the string mask below would hide.
    if code.contains("${") || CREDENTIAL_STORE.is_match(code) {
        return None;
    }
    let masked = mask_strings(code)?;
    if DYNAMIC_CODE.is_match(&masked) || VM_MODULE.is_match(code) {
        return None;
    }
    let in_code = |at: usize| masked.as_bytes().get(at).is_some_and(|byte| *byte != b' ');
    let bases = loopback_bases(code, &masked);
    let mut http_imports = 0usize;
    for found in NODE_NETWORK.find_iter(code) {
        // A network API spelled inside a string is code something may
        // evaluate, which this scan cannot follow.
        if !in_code(found.start()) {
            return None;
        }
        let text = found.as_str();
        if text.starts_with("fetch") {
            let rest = &code[found.start()..];
            let based = FETCH_BASE
                .captures(rest)
                .is_some_and(|call| bases.contains(&call[1]));
            if !based && !FETCH_LITERAL.is_match(rest) {
                return None;
            }
            continue;
        }
        let module = MODULE.captures(text)?;
        if &module[1] != "http" {
            return None;
        }
        // The server constructor is the only member read off this import, so
        // it needs no binding.
        if text.starts_with("require") && REQUIRED_SERVER.is_match(&code[found.end()..]) {
            continue;
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
    let strings: BTreeSet<&str> = STRING_BINDING
        .captures_iter(code)
        .filter_map(|binding| binding.get(1).map(|name| name.as_str()))
        .collect();
    let mut ports = BTreeSet::new();
    for found in URL.find_iter(code) {
        let url = LOOPBACK_URL.captures(&code[found.start()..])?;
        if let Some(port) = url.get(1) {
            ports.insert(port.as_str().parse::<u16>().ok()?);
        }
    }
    for found in LISTEN.find_iter(&masked) {
        let argument = port_expressions::expression(&masked[found.end()..]);
        let port = match port_expressions::literal_port(argument) {
            Some(port) => port,
            None => *constants.get(argument.trim())?,
        };
        let listen = LISTEN_REST.captures(&code[found.end() + argument.len()..])?;
        if let Some(callback) = listen.get(1) {
            if strings.contains(callback.as_str()) {
                return None;
            }
        }
        ports.insert(port);
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

/// The loopback ports the programs `command` (`/bin/sh -c <text>`) launches
/// serve and fetch on, for the workspace sandbox to grant: inline Node
/// source, and a Node script file in the working directory `cwd`, read again
/// as the sandbox is about to run it. Empty when any of those programs uses
/// other network, so the sandbox then withholds the network whole, as it did
/// before.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn launch_loopback_ports(
    command: &[String],
    cwd: Option<&str>,
    home_dir: Option<&str>,
) -> Vec<u16> {
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
    let context = PathContext {
        home_dir,
        cwd,
        ..PathContext::default()
    };
    let mut ports = BTreeSet::new();
    for (index, segment) in model.segments.iter().enumerate() {
        let found = match launched_program(segment) {
            Some((language, Program::Inline(source), false)) => {
                let code = code_lines(language, source);
                match language {
                    Language::Python if python_network(&code) => None,
                    Language::Python => continue,
                    Language::Node if NODE_NETWORK.is_match(&code) => {
                        node_loopback_ports(&code, home_dir)
                    }
                    Language::Node => continue,
                }
            }
            Some((Language::Node, Program::Script(script), false)) => {
                // An earlier directory change moves a relative path out of
                // reach, as it does when the command is judged.
                let moved = model.segments[..index].iter().any(|prior| {
                    prior.executable.as_deref().is_some_and(|value| {
                        matches!(
                            super::super::executable_basename(value),
                            "cd" | "pushd" | "popd"
                        )
                    })
                });
                if moved && !Path::new(script).is_absolute() {
                    continue;
                }
                if may_rewrite(&model.segments, index) {
                    return Vec::new();
                }
                match script_ports(script, context) {
                    Some(found) => found,
                    None => continue,
                }
            }
            _ => continue,
        };
        match found {
            Some(found) => ports.extend(found),
            None => return Vec::new(),
        }
    }
    ports.into_iter().collect()
}

/// Whether any segment but the launch at `launch` could change a file the
/// script loads: anything but a read-only command, or a redirection. An
/// earlier segment runs first, and a later one may run alongside the launch
/// (after `&` or in its pipeline) while Node still loads lazy imports. The
/// grant is read from the files as they are now, so a script that one of
/// these replaces, or one of its imports, would run under a grant read from
/// other text. Matching the writes path by path cannot cover every spelling,
/// import or writer, so any such segment withholds the grant.
pub(super) fn may_rewrite(segments: &[crate::CommandSegmentV1], launch: usize) -> bool {
    segments
        .iter()
        .enumerate()
        .filter(|(other, _)| *other != launch)
        .any(|(_, segment)| {
            segment.text.contains('>')
                || !segment.executable.as_deref().is_some_and(|value| {
                    matches!(
                        super::super::executable_basename(value),
                        "echo"
                            | "printf"
                            | "true"
                            | ":"
                            | "pwd"
                            | "ls"
                            | "cat"
                            | "sleep"
                            | "test"
                            | "["
                            | "cd"
                            | "pushd"
                            | "popd"
                    )
                })
        })
}

/// What the Node script file `script` needs from the network, read the way
/// the command was judged: `None` when it cannot be read or uses no network,
/// and otherwise the loopback ports it earns, if any.
#[cfg_attr(not(unix), allow(dead_code))]
fn script_ports(script: &str, context: PathContext<'_>) -> Option<Option<BTreeSet<u16>>> {
    if !super::read_paths::verified_path_context(context.home_dir, context.cwd) {
        return None;
    }
    let path = super::resolve(script, context)?;
    let (sources, complete) = super::read_graph(Language::Node, Entry::File(path.clone()))?;
    let network = sources
        .iter()
        .any(|source| NODE_NETWORK.is_match(&code_lines(Language::Node, source)));
    network.then(|| {
        (complete && in_working_directory(&path, context))
            .then(|| program_ports(&sources, context.home_dir))
            .flatten()
    })
}

/// Whether the canonical script `path` lies under the working directory,
/// where the workspace scripts a contained command runs live. A script
/// elsewhere earns no loopback grant.
pub(super) fn in_working_directory(path: &Path, context: PathContext<'_>) -> bool {
    context
        .cwd
        .and_then(|cwd| std::fs::canonicalize(cwd).ok())
        .is_some_and(|root| path.starts_with(root))
}

/// The ports a launched program's sources earn: its inline Node source or
/// script when it is loopback-only and no local module it imports uses the
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

#[path = "loopback_ports.rs"]
mod port_expressions;

#[cfg(test)]
#[path = "loopback_tests.rs"]
mod tests;
