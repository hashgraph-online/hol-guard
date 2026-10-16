//! Content-bound launch identity for `python <script>`.
//!
//! A script launch is persistable only when every module it can load is
//! bound: the script and each module found beside it by content (with any
//! cached bytecode Python may run in its place) and each standard module by
//! name. An installed package, a module that loads code by a computed name,
//! evaluates strings, starts processes or reaches the import system keeps
//! the launch once-only, as do a graph that writes files and imports a local
//! module or has the script's directory on the module path, an option or environment variable that loads other code or moves
//! module lookup, and a compiled or extension module beside a source module.
//! The scan (`python_source`) is lexical and errs toward refusal: a refused
//! launch keeps today's approve-once behaviour.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use guard_command::secret_path_probe::is_request_secret_path;
use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
use super::python_modules::{REFUSED_MODULES, STANDARD_MODULES};
use super::python_source::{scan, Import, Replaces};
use super::reasons::{Proof, MUTABLE_LAUNCHER, SENSITIVE_PATH};
use startup::runs_in_place;

/// Single-letter options that run the script without loading other code.
/// `I` and `P` also keep the script's directory off the module path.
const INERT_FLAGS: &str = "bBdEIOPqsSuv";
/// Variables that load code, move module lookup or bytecode, or make the
/// interpreter read more code after the script.
const LOADER_ENVIRONMENT: [&str; 11] = [
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "PYTHONWARNINGS",
    "PYTHONPYCACHEPREFIX",
    "PYTHONPLATLIBDIR",
    "PYTHONEXECUTABLE",
    "PYTHONBREAKPOINT",
    "PYTHONCASEOK",
];
/// Standard submodules that evaluate configuration text or import the
/// names it holds (`logging.config`, `unittest.mock`'s `patch`).
const REFUSED_SUBMODULES: [(&str, &str); 2] = [("logging", "config"), ("unittest", "mock")];
/// Suffixes the import system loads before (or instead of) a `.py` source.
const COMPILED_SUFFIXES: [&str; 4] = ["so", "pyd", "pyc", "pyo"];
const MAX_MODULES: usize = 64;
const MAX_MODULE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LISTING: usize = 4096;

/// What the options before the script change about module lookup.
#[derive(Default)]
struct Options {
    /// `-E` or `-I`: every `PYTHON*` variable is ignored.
    ignore_environment: bool,
    /// `-I` or `-P`: the script's directory is not on the module path.
    safe_path: bool,
    /// `-S`: the `site` module does not run.
    no_site: bool,
    /// `-s` or `-I`: the user site directory is not read.
    no_user_site: bool,
}

/// The script and the options before it, or `None` for an option that loads
/// other code or reads the program elsewhere.
fn script_argument(arguments: &[String]) -> Option<(&str, Options)> {
    let mut options = Options::default();
    for argument in arguments {
        let Some(flags) = argument.strip_prefix('-') else {
            return Some((argument, options));
        };
        if flags.is_empty() || !flags.chars().all(|flag| INERT_FLAGS.contains(flag)) {
            return None;
        }
        options.ignore_environment |= flags.contains(['E', 'I']);
        options.safe_path |= flags.contains(['I', 'P']);
        options.no_site |= flags.contains('S');
        options.no_user_site |= flags.contains(['I', 's']);
    }
    None
}

struct Graph<'a> {
    ctx: &'a Ctx<'a>,
    cwd: &'a str,
    /// The script's directory: the first module-path entry.
    root: String,
    script_directory: bool,
    modules: BTreeMap<String, String>,
    bytecode: BTreeMap<String, String>,
    /// Code `site` runs before the script: `.pth` files, the modules they
    /// import, and `sitecustomize`/`usercustomize`.
    startup: BTreeMap<String, String>,
    /// Each startup shim's functions that load a package by name.
    shim_loaders: Vec<(String, BTreeSet<String>)>,
    /// Each startup source and `.pth` import line, as names it uses.
    startup_code: Vec<(String, String)>,
    /// What the startup sources' `.replace` calls can do together.
    startup_replaces: Replaces,
    standard: BTreeSet<String>,
    listings: BTreeMap<String, Vec<String>>,
    queue: VecDeque<String>,
    total: u64,
}

impl Graph<'_> {
    fn digest(&mut self, path: &str) -> Proof<(String, Vec<u8>)> {
        self.ctx.check()?;
        let resolved = fs_path::resolve_strict(path).ok_or(MUTABLE_LAUNCHER)?;
        for candidate in [path, resolved.as_str()] {
            if is_request_secret_path(
                candidate,
                Some(Path::new(self.cwd)),
                self.ctx.home.map(Path::new),
            ) {
                return Err(SENSITIVE_PATH);
            }
        }
        let bytes = fs_path::read_bounded(&resolved, MAX_MODULE_BYTES).ok_or(MUTABLE_LAUNCHER)?;
        self.total += bytes.len() as u64;
        if self.total > MAX_TOTAL_BYTES {
            return Err(MUTABLE_LAUNCHER);
        }
        Ok((fs_path::sha256_hex(&bytes), bytes))
    }

    fn listing(&mut self, directory: &str) -> Proof<&Vec<String>> {
        self.listing_within(directory, MAX_LISTING)
    }

    fn listing_within(&mut self, directory: &str, limit: usize) -> Proof<&Vec<String>> {
        if !self.listings.contains_key(directory) {
            self.ctx.check()?;
            let mut names = Vec::new();
            if let Ok(entries) = std::fs::read_dir(directory) {
                for entry in entries {
                    let name = entry.map_err(|_| MUTABLE_LAUNCHER)?.file_name();
                    names.push(name.into_string().map_err(|_| MUTABLE_LAUNCHER)?);
                    if names.len() > limit {
                        return Err(MUTABLE_LAUNCHER);
                    }
                }
            }
            self.listings.insert(directory.to_owned(), names);
        }
        Ok(&self.listings[directory])
    }

    /// The source the import system loads for `name` in `directory`: a
    /// package's `__init__.py` or a `.py` module. `None` when neither exists
    /// (or only a namespace directory does); an error when compiled or
    /// extension code could load in the source's place.
    fn find(&mut self, directory: &str, name: &str) -> Proof<Option<String>> {
        let entries = self.listing(directory)?;
        let shadowed = entries.iter().any(|entry| {
            entry
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('.'))
                .and_then(|rest| rest.rsplit('.').next())
                .is_some_and(|suffix| COMPILED_SUFFIXES.contains(&suffix))
        });
        let has_entry = entries.iter().any(|entry| entry == name);
        let has_module = entries
            .iter()
            .any(|entry| entry.strip_suffix(".py") == Some(name));
        if shadowed {
            return Err(MUTABLE_LAUNCHER);
        }
        let package = fs_path::join(directory, name);
        if has_entry && fs_path::is_dir(&package) {
            if let Some(init) = self.find(&package, "__init__")? {
                return Ok(Some(init));
            }
        }
        let module = fs_path::join(directory, &format!("{name}.py"));
        Ok((has_module && fs_path::is_file(&module)).then_some(module))
    }

    /// Queue a module and bind the cached bytecode Python may run in its
    /// place.
    fn add_module(&mut self, path: String) -> Proof<()> {
        if self.modules.contains_key(&path) || self.queue.contains(&path) {
            return Ok(());
        }
        if self.modules.len() + self.queue.len() >= MAX_MODULES {
            return Err(MUTABLE_LAUNCHER);
        }
        self.add_bytecode(&path)?;
        self.queue.push_back(path);
        Ok(())
    }

    /// Bind each cached `.pyc` the import system would run in place of the
    /// source at `path`. A stale timestamp file is skipped: Python ignores it
    /// and writes a fresh one, so binding it would only change the identity.
    fn add_bytecode(&mut self, path: &str) -> Proof<()> {
        let stem = fs_path::name(path)
            .strip_suffix(".py")
            .ok_or(MUTABLE_LAUNCHER)?
            .to_owned();
        let cache = fs_path::join(&fs_path::parent(path), "__pycache__");
        if !fs_path::is_dir(&cache) {
            return Ok(());
        }
        let cached: Vec<String> = self
            .listing(&cache)?
            .iter()
            .filter(|entry| {
                entry
                    .strip_prefix(stem.as_str())
                    .is_some_and(|rest| rest.starts_with('.') && rest.ends_with(".pyc"))
            })
            .cloned()
            .collect();
        if cached.is_empty() {
            return Ok(());
        }
        let source = std::fs::metadata(path).map_err(|_| MUTABLE_LAUNCHER)?;
        for entry in cached {
            let file = fs_path::join(&cache, &entry);
            if runs_in_place(&source, &file) {
                let (digest, _) = self.digest(&file)?;
                self.bytecode.insert(file, digest);
            }
        }
        Ok(())
    }

    /// Bind `parts` below `directory` (each package's `__init__.py` and the
    /// last module) and any submodule a `from` import takes by name. Every
    /// part must exist as source.
    fn add_local(&mut self, directory: &str, parts: &[&str], names: &[String]) -> Proof<()> {
        let mut directory = directory.to_owned();
        let mut is_package = true;
        for part in parts {
            if !is_package {
                return Err(MUTABLE_LAUNCHER);
            }
            let source = self.find(&directory, part)?.ok_or(MUTABLE_LAUNCHER)?;
            is_package = fs_path::name(&source) == "__init__.py";
            directory = fs_path::parent(&source);
            self.add_module(source)?;
        }
        if is_package {
            for name in names {
                if let Some(source) = self.find(&directory, name)? {
                    self.add_module(source)?;
                }
            }
        }
        Ok(())
    }

    fn resolve(&mut self, importer: &str, is_script: bool, import: &Import) -> Proof<()> {
        let parts: Vec<&str> = import
            .module
            .split('.')
            .filter(|part| !part.is_empty())
            .collect();
        if import.level > 0 {
            // A relative import resolves inside the importer's package, which
            // must sit below the script's directory.
            let mut directory = fs_path::parent(importer);
            for _ in 1..import.level {
                directory = fs_path::parent(&directory);
            }
            if is_script || directory == self.root || !fs_path::is_inside(&directory, &self.root) {
                return Err(MUTABLE_LAUNCHER);
            }
            return self.add_local(&directory, &parts, &import.names);
        }
        let top = *parts.first().ok_or(MUTABLE_LAUNCHER)?;
        let refused_submodule = REFUSED_SUBMODULES.iter().any(|(package, module)| {
            top == *package
                && (parts.get(1) == Some(module)
                    || (parts.len() == 1 && import.names.iter().any(|name| name == module)))
        });
        if REFUSED_MODULES.contains(&top) || refused_submodule {
            return Err(MUTABLE_LAUNCHER);
        }
        if self.script_directory {
            let root = self.root.clone();
            if self.find(&root, top)?.is_some() {
                return self.add_local(&root, &parts, &import.names);
            }
        }
        if STANDARD_MODULES.contains(&top) {
            self.standard.insert(top.to_owned());
            return Ok(());
        }
        Err(MUTABLE_LAUNCHER)
    }
}

/// The bound module graph of `python <script>`, or the reason it stays
/// once-only. `executable` is the interpreter's verified launch identity.
pub(super) fn python_script(
    arguments: &[String],
    cwd: &str,
    ctx: &Ctx,
    executable: &Value,
) -> Proof<Value> {
    let (script, mut options) = script_argument(arguments).ok_or(MUTABLE_LAUNCHER)?;
    for (name, value) in ctx.env {
        if value.is_empty() {
            continue;
        }
        if LOADER_ENVIRONMENT
            .iter()
            .any(|refused| name.eq_ignore_ascii_case(refused))
        {
            return Err(MUTABLE_LAUNCHER);
        }
        if options.ignore_environment {
            continue;
        }
        if name.eq_ignore_ascii_case("PYTHONSAFEPATH") {
            options.safe_path = true;
        }
        if name.eq_ignore_ascii_case("PYTHONNOUSERSITE") {
            options.no_user_site = true;
        }
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
    if !fs_path::name(&resolved).ends_with(".py") {
        return Err(MUTABLE_LAUNCHER);
    }
    let mut graph = Graph {
        ctx,
        cwd,
        // CPython puts the real path's directory first on the module path,
        // so a symlinked script imports beside its target, not the link.
        root: fs_path::parent(&resolved),
        script_directory: !options.safe_path,
        modules: BTreeMap::new(),
        bytecode: BTreeMap::new(),
        startup: BTreeMap::new(),
        shim_loaders: Vec::new(),
        startup_code: Vec::new(),
        startup_replaces: Replaces::default(),
        standard: BTreeSet::new(),
        listings: BTreeMap::new(),
        queue: VecDeque::new(),
        total: 0,
    };
    // Python never runs cached bytecode for the script itself.
    graph.queue.push_back(resolved.clone());
    let mut writes = false;
    let mut replaces = Replaces::default();
    while let Some(module) = graph.queue.pop_front() {
        let (digest, bytes) = graph.digest(&module)?;
        let source = String::from_utf8(bytes).map_err(|_| MUTABLE_LAUNCHER)?;
        let scanned = scan(source.trim_start_matches('\u{feff}')).ok_or(MUTABLE_LAUNCHER)?;
        graph.modules.insert(module.clone(), digest);
        writes |= scanned.writes;
        replaces = replaces.join(scanned.replaces);
        for import in &scanned.imports {
            graph.resolve(&module, module == resolved, import)?;
        }
    }
    // A local module is bound as it was before launch; a graph that can
    // write files could replace one before it is imported, or create one
    // beside the script that shadows a standard module.
    if (writes || replaces.writes()) && (graph.modules.len() > 1 || graph.script_directory) {
        return Err(MUTABLE_LAUNCHER);
    }
    if !options.no_site {
        graph.add_startup(executable, !options.no_user_site)?;
    }
    let entries = |map: &BTreeMap<String, String>| -> Vec<Value> {
        map.iter()
            .map(|(path, digest)| json!({"path": path, "sha256": digest}))
            .collect()
    };
    Ok(json!({
        "script": resolved,
        "modules": entries(&graph.modules),
        "bytecode": entries(&graph.bytecode),
        "startup": entries(&graph.startup),
        "standard": graph.standard.into_iter().collect::<Vec<_>>(),
    }))
}

#[path = "python_startup.rs"]
mod startup;

#[cfg(all(test, unix))]
#[path = "python_script_tests.rs"]
mod tests;
