//! `runner_authority` kind `local_cli_script_source`: the files Guard reads,
//! but never runs, to learn what a script takes (`local_cli_script_source.py`
//! before it moved here).
//!
//! A script's own source says what it takes and whether it answers `--help`
//! before anything runs it. This kind only finds and reads the files: the
//! verified script itself, and the few local modules it imports from inside
//! its own folder.
//!
//! - `probe` says whether a path may be probed at all: an absolute path to a
//!   regular file, outside `/proc`, `/dev` and `/sys`.
//! - `read` returns the start of a script's text; with `shebang_only` the file
//!   must start with a `#!` line, so a compiled program is never read as text.
//! - `imports` keeps the `./`-relative imports worth reading: regular script
//!   files that still land inside the script's folder once resolved.
//! - `module` reads one of those modules, only when the file opened is the one
//!   inside the script's folder; the final link is never followed.
//! - `mcp_evidence` says whether a script serves MCP, from its own source, the
//!   local modules it imports, or, for the wrapper pip or uv writes for an
//!   installed command, the installed package the wrapper runs
//!   (`local_mcp_source_evidence.py` before it moved here).
//!
//! Paths resolve the way Python's `Path.resolve` does, so the files named in
//! answers are spelled as Python spelled them.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::daemon_lifecycle_text::py_strip;
use crate::guard_paths::{python_realpath, python_realpath_lax};
use crate::local_cli_help::mcp_source_facts;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SCRIPT_SOURCE_LIMIT: u64 = 32 * 1024;
/// Enough for an entry point that hands its arguments to a module beside it,
/// and few enough that a script importing many files is not read in full.
const MAX_FOLLOWED_IMPORTS: usize = 4;
const SCRIPT_SUFFIXES: [&str; 11] = [
    ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py", ".rb", ".sh", ".bash", ".zsh",
];
/// Python files read from the package an entry-point wrapper runs.
const MAX_PACKAGE_FILES: usize = 24;
/// Kernel file systems a probe never reads, whatever links lead there.
const KERNEL_ROOTS: [&str; 3] = ["proc", "dev", "sys"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let keys: &[&str] = match op {
        "probe" => &["op", "path"],
        "read" => &["op", "path", "shebang_only"],
        "imports" => &["op", "script", "imports"],
        "module" => &["op", "module", "script"],
        "mcp_evidence" => &["op", "script", "invocation"],
        _ => return Err(ERR_INVALID),
    };
    if fields.len() != keys.len() || !keys.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    match op {
        "probe" => Ok(json!({ "safe": safe_probe_path(text(fields, "path")?) })),
        "read" => {
            let shebang_only = fields
                .get("shebang_only")
                .and_then(Value::as_bool)
                .ok_or(ERR_INVALID)?;
            let source = read_script_source(text(fields, "path")?, shebang_only);
            Ok(json!({ "text": source }))
        }
        "imports" => {
            let imports = texts(fields, "imports")?;
            let paths = local_import_paths(text(fields, "script")?, &imports);
            Ok(json!({ "paths": paths }))
        }
        "mcp_evidence" => {
            let invocation: Vec<String> = texts(fields, "invocation")?
                .into_iter()
                .map(str::to_owned)
                .collect();
            let serves = script_serves_mcp(text(fields, "script")?, &invocation);
            Ok(json!({ "serves": serves }))
        }
        _ => {
            let source = read_local_module(text(fields, "module")?, text(fields, "script")?);
            Ok(json!({ "text": source }))
        }
    }
}

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn texts<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<Vec<&'a str>, &'static str> {
    fields
        .get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|entry| entry.as_str().ok_or(ERR_INVALID))
        .collect()
}

fn spelled(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `Path.resolve(strict=True)`: `None` where Python raises.
fn resolve_strict(path: &Path) -> Option<PathBuf> {
    python_realpath(path).ok().flatten()
}

/// `Path.is_file()`: follows links, and any error reads as not a file.
fn is_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

/// `Path.suffix`: the final component's last dotted part, never a leading dot.
fn suffix(path: &Path) -> String {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if !extension.is_empty() => format!(".{extension}"),
        _ => String::new(),
    }
}

/// `PurePath.is_relative_to`, which ignores case on Windows.
fn is_within(path: &Path, folder: &Path) -> bool {
    if cfg!(windows) {
        let lowered = |path: &Path| PathBuf::from(spelled(path).to_lowercase());
        lowered(path).starts_with(lowered(folder))
    } else {
        path.starts_with(folder)
    }
}

/// The decoded text of a read, or `None` when it is blank, as `str.strip`
/// sees it.
fn decoded(raw: &[u8]) -> Option<String> {
    let source = String::from_utf8_lossy(raw).into_owned();
    let blank = source
        .chars()
        .all(|character| character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character));
    (!blank).then_some(source)
}

fn read_limited(file: File) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    file.take(SCRIPT_SOURCE_LIMIT).read_to_end(&mut raw).ok()?;
    Some(raw)
}

/// The file an absolute path resolves to, when it is a regular file outside
/// the kernel's virtual file systems.
fn probe_target(path_text: &str) -> Option<PathBuf> {
    let path = Path::new(path_text);
    if path_text.is_empty() || !path.is_absolute() {
        return None;
    }
    let resolved = python_realpath_lax(path).ok()?;
    if !is_file(&resolved) {
        return None;
    }
    let mut components = resolved.components();
    let kernel = matches!(components.next(), Some(Component::RootDir))
        && components.next().is_some_and(|part| {
            let name = part.as_os_str().to_string_lossy().to_lowercase();
            KERNEL_ROOTS.contains(&name.as_str())
        });
    (!kernel).then_some(resolved)
}

fn safe_probe_path(path_text: &str) -> bool {
    probe_target(path_text).is_some()
}

/// A script's text, read only from the regular file its path resolved to
/// when it was checked: a link swapped in after the check is not followed.
fn read_script_source(path: &str, shebang_only: bool) -> Option<String> {
    let resolved = probe_target(path)?;
    let opened = open_no_follow(&resolved).ok()?;
    let regular = opened.metadata().is_ok_and(|metadata| metadata.is_file());
    if !regular || !same_file(&opened, &resolved) {
        return None;
    }
    let raw = read_limited(opened)?;
    if shebang_only && !raw.starts_with(b"#!") {
        return None;
    }
    decoded(&raw)
}

/// Opens `path` for reading without following its final link where the
/// platform can refuse one; Python passes `O_NOFOLLOW` only where it exists.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

/// Whether the open file is the file `resolved` names now.
#[cfg(unix)]
fn same_file(opened: &File, resolved: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (opened.metadata(), std::fs::metadata(resolved)) {
        (Ok(left), Ok(right)) => left.dev() == right.dev() && left.ino() == right.ino(),
        _ => false,
    }
}

#[cfg(windows)]
fn same_file(opened: &File, resolved: &Path) -> bool {
    match (
        guard_runtime_windows_process::handle_file_id(opened),
        guard_runtime_windows_process::regular_file_id(resolved, true),
    ) {
        (Ok(left), Ok((right, _))) => left == right,
        _ => false,
    }
}

#[cfg(not(any(unix, windows)))]
fn same_file(_opened: &File, _resolved: &Path) -> bool {
    false
}

/// A module's text, read only when the file opened is the one inside the
/// script's folder.
///
/// `module` was checked when it was found, but a symlink can be swapped in
/// before it is opened. The final link is never followed, and the open file
/// must be the same regular file that its path resolves to now, inside the
/// folder that holds the script.
fn read_local_module(module: &str, script: &str) -> Option<String> {
    let script = resolve_strict(Path::new(script))?;
    let folder = script.parent()?;
    let opened = open_no_follow(Path::new(module)).ok()?;
    let regular = opened.metadata().is_ok_and(|metadata| metadata.is_file());
    let resolved = resolve_strict(Path::new(module))?;
    if !regular || !is_within(&resolved, folder) || !same_file(&opened, &resolved) {
        return None;
    }
    decoded(&read_limited(opened)?)
}

/// The imported modules worth reading: regular script files inside the
/// script's folder.
///
/// `imports` are the `./`-relative paths the resident read out of the source,
/// so they are text the script chose. Each is resolved through symlinks and
/// kept only when it still lands inside the folder that holds the script
/// itself, which keeps the read away from the rest of the disk.
fn local_import_paths(script: &str, imports: &[&str]) -> Vec<String> {
    let Some(script_path) = resolve_strict(Path::new(script)) else {
        return Vec::new();
    };
    let Some(folder) = script_path.parent() else {
        return Vec::new();
    };
    let script_suffix = suffix(&script_path);
    let mut found: Vec<PathBuf> = Vec::new();
    for entry in imports {
        if found.len() >= MAX_FOLLOWED_IMPORTS {
            break;
        }
        if let Some(module) = local_module(folder, entry, &script_suffix) {
            if module != script_path && !found.contains(&module) {
                found.push(module);
            }
        }
    }
    found.iter().map(|path| spelled(path)).collect()
}

fn local_module(folder: &Path, entry: &str, script_suffix: &str) -> Option<PathBuf> {
    let relative = entry.strip_prefix("./")?;
    if entry.contains('\0') {
        return None;
    }
    let mut candidates = vec![folder.join(relative)];
    // `import './cli'` names the file without the suffix it shares with the script.
    if !script_suffix.is_empty() && suffix(Path::new(relative)).is_empty() {
        candidates.push(folder.join(format!("{relative}{script_suffix}")));
    }
    // `from server import mcp` reads ./server.py, which may be a package.
    if let Some(package) = relative.strip_suffix(".py") {
        candidates.push(folder.join(package).join("__init__.py"));
    }
    candidates.into_iter().find_map(|candidate| {
        let resolved = resolve_strict(&candidate)?;
        let script_file = SCRIPT_SUFFIXES.contains(&suffix(&resolved).to_lowercase().as_str());
        (is_within(&resolved, folder) && script_file && safe_probe_path(&spelled(&resolved)))
            .then_some(resolved)
    })
}

/// Whether Guard may launch `script` to ask it for MCP tools.
///
/// Recognizing a command as MCP launches it with its real arguments, so a
/// script that is not a server would do its normal work. Only a script whose
/// source, or a local module it imports, shows an MCP server is launched; for
/// the entry-point wrapper pip or uv writes for an installed command, the
/// installed package the wrapper runs must show one. A script whose source
/// cannot be read is never launched.
fn script_serves_mcp(script: &str, invocation: &[String]) -> bool {
    let Some(text) = read_script_source(script, false) else {
        return false;
    };
    let (mcp_server, entry_point, imports) = mcp_source_facts(&text, invocation);
    if mcp_server {
        return true;
    }
    let imports: Vec<&str> = imports.iter().map(String::as_str).collect();
    let modules = local_import_paths(script, &imports);
    if let Some(module) = entry_point.filter(|_| modules.is_empty()) {
        return package_serves_mcp(&module, script, &text, invocation);
    }
    modules.iter().any(|module| {
        read_local_module(module, script)
            .is_some_and(|source| mcp_source_facts(&source, invocation).0)
    })
}

/// Whether the module an entry-point wrapper runs shows an MCP server.
///
/// The module is looked up in the `site-packages` of the environment that
/// holds the wrapper or its `#!` interpreter, as pip, pipx and `uv tool` lay
/// them out. Its own file is read, then the modules of the same package it
/// imports, up to [`MAX_PACKAGE_FILES`] in all. Another module in the package,
/// such as an optional MCP server beside a CLI's commands, does not count. A
/// module Guard cannot find is not launched.
fn package_serves_mcp(module: &str, wrapper: &str, text: &str, invocation: &[String]) -> bool {
    let parts: Vec<&str> = module.split('.').collect();
    let top = parts[0];
    for site in site_packages(wrapper, text) {
        let base = parts
            .iter()
            .fold(site.clone(), |path, part| path.join(part));
        let Some(entry) = [base.join("__init__.py"), base.with_extension("py")]
            .into_iter()
            .find(|path| is_file(path))
        else {
            continue;
        };
        let package = site.join(top).join("__init__.py");
        let anchor = spelled(if is_file(&package) { &package } else { &entry });
        let mut queue = VecDeque::from([spelled(&entry)]);
        let mut seen: HashSet<String> = queue.iter().cloned().collect();
        while let Some(path) = queue.pop_front() {
            let Some(source) = read_local_module(&path, &anchor) else {
                continue;
            };
            let (mcp_server, _, imports) = mcp_source_facts(&source, invocation);
            if mcp_server {
                return true;
            }
            for imported in package_imports(&path, &imports, &site, top) {
                if !seen.contains(&imported) && seen.len() < MAX_PACKAGE_FILES {
                    seen.insert(imported.clone());
                    queue.push_back(imported);
                }
            }
        }
        return false;
    }
    false
}

/// The modules of package `top` that the file at `path` imports.
///
/// The source read reports `from .server import serve` as `./server.py`,
/// beside `path`, and `from top.server import serve` as `./top/server.py`,
/// under `site`. Both are read only inside the package.
fn package_imports(path: &str, imports: &[String], site: &Path, top: &str) -> Vec<String> {
    let initializer = site.join(top).join("__init__.py");
    let Some(package) =
        resolve_strict(&initializer).and_then(|file| file.parent().map(Path::to_path_buf))
    else {
        return Vec::new();
    };
    let Some(folder) = resolve_strict(Path::new(path))
        .and_then(|file| file.parent().map(Path::to_path_buf))
        .and_then(|folder| folder.strip_prefix(&package).ok().map(Path::to_path_buf))
    else {
        return Vec::new();
    };
    let in_top = format!("./{top}/");
    let entries: Vec<String> = imports
        .iter()
        .map(|entry| match entry.strip_prefix(&in_top) {
            Some(rest) => format!("./{rest}"),
            None => {
                let rest = entry.strip_prefix("./").unwrap_or(entry);
                format!("./{}", spelled(&folder.join(rest)).replace('\\', "/"))
            }
        })
        .collect();
    let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
    local_import_paths(&spelled(&initializer), &entries)
}

/// The `site-packages` folders of the environments a wrapper may belong to.
fn site_packages(wrapper: &str, text: &str) -> Vec<PathBuf> {
    fn grandparent(path: &Path) -> PathBuf {
        let up = |path: &Path| path.parent().unwrap_or(path).to_path_buf();
        up(&up(path))
    }
    let wrapper_path = Path::new(wrapper);
    let mut prefixes = vec![grandparent(wrapper_path)];
    if let Ok(resolved) = python_realpath_lax(wrapper_path) {
        prefixes.push(grandparent(&resolved));
    }
    let first = text.split('\n').next().unwrap_or("");
    if let Some(rest) = first.strip_prefix("#!") {
        let interpreter = py_strip(rest).split(' ').next().unwrap_or("");
        let named_python = Path::new(interpreter)
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("python"));
        if interpreter.starts_with('/') && named_python {
            prefixes.push(grandparent(Path::new(interpreter)));
        }
    }
    let mut found: Vec<PathBuf> = Vec::new();
    let mut visited: Vec<&PathBuf> = Vec::new();
    for prefix in &prefixes {
        if visited.contains(&prefix) {
            continue;
        }
        visited.push(prefix);
        let mut sites = python_site_folders(prefix);
        sites.push(prefix.join("Lib").join("site-packages"));
        for site in sites {
            if site.is_dir() && !found.contains(&site) {
                found.push(site);
            }
        }
    }
    found
}

/// `prefix.glob("lib/python3*/site-packages")`, in sorted order.
fn python_site_folders(prefix: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(prefix.join("lib")) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            if cfg!(windows) {
                name.to_lowercase().starts_with("python3")
            } else {
                name.starts_with("python3")
            }
        })
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| prefix.join("lib").join(name).join("site-packages"))
        .filter(|site| site.exists())
        .collect()
}

#[cfg(all(test, unix))]
#[path = "local_cli_script_source_tests.rs"]
mod tests;
