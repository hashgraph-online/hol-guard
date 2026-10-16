//! Content-bound launch identity for `node <script>`.
//!
//! A script launch is persistable only when every module it can load is bound:
//! the script and each relative import by content, each package import by its
//! installed manifest (the `runner-local-bin` standard) and each builtin by
//! name. A module that loads code by a computed name, evaluates strings,
//! starts processes or reaches the module loader keeps the launch once-only,
//! as do a graph that writes files and loads a local module at run time, and
//! `NODE_OPTIONS` and `NODE_PATH`. The scan (`node_source`) is lexical and
//! errs toward refusal: a refused launch keeps today's approve-once behaviour.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use guard_command::secret_path_probe::is_request_secret_path;
use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
use super::node_source::{module_specifiers, source_writes_files};
use super::reasons::{Proof, MUTABLE_LAUNCHER, SENSITIVE_PATH};

pub(super) const NODE_LAUNCHERS: [&str; 2] = ["node", "nodejs"];

/// The options `node` accepts before the script without loading other code
/// (the launch-identity engine's own list).
const INERT_OPTIONS: [&str; 10] = [
    "--abort-on-uncaught-exception",
    "--enable-source-maps",
    "--no-addons",
    "--no-deprecation",
    "--no-warnings",
    "--trace-deprecation",
    "--trace-uncaught",
    "--trace-warnings",
    "--use-bundled-ca",
    "--use-openssl-ca",
];
/// Preload code or move package lookup outside the bound tree.
const LOADER_ENVIRONMENT: [&str; 2] = ["NODE_OPTIONS", "NODE_PATH"];
const SOURCE_EXTENSIONS: [&str; 6] = ["js", "mjs", "cjs", "ts", "mts", "cts"];
/// CommonJS file resolution order; `.node` (a native addon) is refused.
const REQUIRE_SUFFIXES: [&str; 4] = ["", ".js", ".json", ".node"];
const MAX_MODULES: usize = 64;
const MAX_MODULE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Builtins a script may import by bare or `node:` name.
const BUILTINS: &[&str] = &[
    "assert",
    "assert/strict",
    "async_hooks",
    "buffer",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "dns/promises",
    "events",
    "fs",
    "fs/promises",
    "http",
    "http2",
    "https",
    "net",
    "os",
    "path",
    "path/posix",
    "path/win32",
    "perf_hooks",
    "process",
    "querystring",
    "readline",
    "readline/promises",
    "stream",
    "stream/consumers",
    "stream/promises",
    "stream/web",
    "string_decoder",
    "timers",
    "timers/promises",
    "tls",
    "tty",
    "url",
    "util",
    "util/types",
    "zlib",
];

/// Builtins that load or evaluate code, and legacy names. A bare specifier
/// naming one still resolves to the builtin, never to an installed package.
const REFUSED_BUILTINS: &[&str] = &[
    "child_process",
    "cluster",
    "domain",
    "inspector",
    "inspector/promises",
    "module",
    "punycode",
    "repl",
    "sys",
    "trace_events",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
];

/// The `node` arguments' script, or `None` for any option that loads code.
fn script_argument(arguments: &[String]) -> Option<&str> {
    for argument in arguments {
        if argument == "--" {
            continue;
        }
        if INERT_OPTIONS.contains(&argument.as_str()) {
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        return Some(argument);
    }
    None
}

fn extension(path: &str) -> String {
    fs_path::name(path)
        .rsplit_once('.')
        .map_or(String::new(), |(_, ext)| ext.to_lowercase())
}

fn is_relative(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../") || specifier.starts_with('/')
}

/// A package specifier's name: `pkg` or `@scope/pkg`.
fn package_name(specifier: &str) -> Option<String> {
    let mut parts = specifier.split('/');
    let first = parts.next()?;
    let name = if first.starts_with('@') {
        format!("{first}/{}", parts.next()?)
    } else {
        first.to_owned()
    };
    super::runner_bin::package_name_pattern()
        .is_match(&name)
        .then_some(name)
}

struct Graph<'a> {
    ctx: &'a Ctx<'a>,
    cwd: &'a str,
    modules: BTreeMap<String, String>,
    data: BTreeMap<String, String>,
    packages: BTreeMap<String, String>,
    builtins: BTreeSet<String>,
    queue: VecDeque<String>,
    total: u64,
}

impl Graph<'_> {
    fn digest(&mut self, path: &str, limit: u64) -> Proof<(String, Vec<u8>)> {
        self.ctx.check()?;
        if is_request_secret_path(
            path,
            Some(Path::new(self.cwd)),
            self.ctx.home.map(Path::new),
        ) {
            return Err(SENSITIVE_PATH);
        }
        let bytes = fs_path::read_bounded(path, limit).ok_or(MUTABLE_LAUNCHER)?;
        self.total += bytes.len() as u64;
        if self.total > MAX_TOTAL_BYTES {
            return Err(MUTABLE_LAUNCHER);
        }
        Ok((fs_path::sha256_hex(&bytes), bytes))
    }

    /// Queue a module file, binding the package scope that sets its format.
    fn add_module(&mut self, path: String) -> Proof<()> {
        if self.modules.contains_key(&path) || self.queue.contains(&path) {
            return Ok(());
        }
        if self.modules.len() + self.queue.len() >= MAX_MODULES {
            return Err(MUTABLE_LAUNCHER);
        }
        for parent in fs_path::parents(&path) {
            let manifest = fs_path::join(&parent, "package.json");
            if fs_path::is_file(&manifest) {
                if !self.data.contains_key(&manifest) {
                    let (digest, _) = self.digest(&manifest, MAX_MANIFEST_BYTES)?;
                    self.data.insert(manifest, digest);
                }
                break;
            }
        }
        self.queue.push_back(path);
        Ok(())
    }

    fn resolve_file(&mut self, importer: &str, specifier: &str) -> Proof<()> {
        let base = if fs_path::is_abs(specifier) {
            specifier.to_owned()
        } else {
            fs_path::join(&fs_path::parent(importer), specifier)
        };
        let resolved = REQUIRE_SUFFIXES
            .iter()
            .map(|suffix| format!("{base}{suffix}"))
            .find(|candidate| fs_path::is_file(candidate))
            .ok_or(MUTABLE_LAUNCHER)?;
        let resolved = fs_path::resolve_strict(&resolved).ok_or(MUTABLE_LAUNCHER)?;
        match extension(&resolved).as_str() {
            "json" => {
                if !self.data.contains_key(&resolved) {
                    let (digest, _) = self.digest(&resolved, MAX_MODULE_BYTES)?;
                    self.data.insert(resolved, digest);
                }
                Ok(())
            }
            ext if SOURCE_EXTENSIONS.contains(&ext) => self.add_module(resolved),
            _ => Err(MUTABLE_LAUNCHER),
        }
    }

    /// Bind the installed manifest the nearest `node_modules` lookup finds.
    fn resolve_package(&mut self, importer: &str, name: &str) -> Proof<()> {
        for parent in fs_path::parents(importer) {
            if fs_path::name(&parent) == "node_modules" {
                continue;
            }
            let package = name
                .split('/')
                .fold(fs_path::join(&parent, "node_modules"), |dir, part| {
                    fs_path::join(&dir, part)
                });
            let manifest = fs_path::join(&package, "package.json");
            if fs_path::is_file(&manifest) {
                let (digest, _) = self.digest(&manifest, MAX_MANIFEST_BYTES)?;
                self.packages.insert(manifest, digest);
                return Ok(());
            }
        }
        Err(MUTABLE_LAUNCHER)
    }

    fn resolve(&mut self, importer: &str, specifier: &str) -> Proof<()> {
        let builtin = specifier.strip_prefix("node:").unwrap_or(specifier);
        if BUILTINS.contains(&builtin) {
            self.builtins.insert(builtin.to_owned());
            return Ok(());
        }
        if specifier.starts_with("node:") || REFUSED_BUILTINS.contains(&builtin) {
            return Err(MUTABLE_LAUNCHER);
        }
        if is_relative(specifier) {
            return self.resolve_file(importer, specifier);
        }
        let name = package_name(specifier).ok_or(MUTABLE_LAUNCHER)?;
        self.resolve_package(importer, &name)
    }
}

/// The bound module graph of `node <script>`, or the reason it stays once-only.
pub(super) fn node_script(arguments: &[String], cwd: &str, ctx: &Ctx) -> Proof<Value> {
    if LOADER_ENVIRONMENT
        .iter()
        .any(|name| ctx.env.get(*name).is_some_and(|value| !value.is_empty()))
    {
        return Err(MUTABLE_LAUNCHER);
    }
    let script = script_argument(arguments).ok_or(MUTABLE_LAUNCHER)?;
    if script == "-" {
        return Err(MUTABLE_LAUNCHER);
    }
    let candidate = if fs_path::is_abs(script) {
        script.to_owned()
    } else {
        fs_path::join(cwd, script)
    };
    if !fs_path::is_file(&candidate) {
        return Err(MUTABLE_LAUNCHER);
    }
    let resolved = fs_path::resolve_strict(&candidate).ok_or(MUTABLE_LAUNCHER)?;
    if !SOURCE_EXTENSIONS.contains(&extension(&resolved).as_str()) {
        return Err(MUTABLE_LAUNCHER);
    }
    let mut graph = Graph {
        ctx,
        cwd,
        modules: BTreeMap::new(),
        data: BTreeMap::new(),
        packages: BTreeMap::new(),
        builtins: BTreeSet::new(),
        queue: VecDeque::new(),
        total: 0,
    };
    graph.add_module(resolved.clone())?;
    let (mut writes, mut loads_local_at_run_time) = (false, false);
    while let Some(module) = graph.queue.pop_front() {
        let (digest, bytes) = graph.digest(&module, MAX_MODULE_BYTES)?;
        let source = String::from_utf8(bytes).map_err(|_| MUTABLE_LAUNCHER)?;
        graph.modules.insert(module.clone(), digest);
        writes |= source_writes_files(&source);
        for specifier in module_specifiers(&source).ok_or(MUTABLE_LAUNCHER)? {
            loads_local_at_run_time |= specifier.runtime && is_relative(&specifier.name);
            graph.resolve(&module, &specifier.name)?;
        }
    }
    // A module loaded at run time is bound as it was before launch; a graph
    // that can write files could replace it first.
    if writes && loads_local_at_run_time {
        return Err(MUTABLE_LAUNCHER);
    }
    let entries = |map: &BTreeMap<String, String>| -> Vec<Value> {
        map.iter()
            .map(|(path, digest)| json!({"path": path, "sha256": digest}))
            .collect()
    };
    Ok(json!({
        "script": resolved,
        "modules": entries(&graph.modules),
        "data": entries(&graph.data),
        "packages": entries(&graph.packages),
        "builtins": graph.builtins.into_iter().collect::<Vec<_>>(),
    }))
}

#[cfg(all(test, unix))]
#[path = "node_script_tests.rs"]
mod tests;
