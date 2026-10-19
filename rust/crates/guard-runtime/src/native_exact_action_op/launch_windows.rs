//! Windows launch proofs for exact-action approvals.
//!
//! A shell launch on Windows is persistable only when the harness runs it
//! through a POSIX shell (Claude Code's Git Bash, the Pi family's bash) and
//! the command starts a native image that shell and Guard resolve to the same
//! file. The resident engine binds the image itself; this proof adds what the
//! Windows loader reads beside it: the DLLs, manifests and .NET host files of
//! the application directory, unless that directory sits under an
//! administrator-owned install root, and the DLLs of the working directory,
//! which the default DLL search order reaches after the system directories,
//! with the executables there a bare-name child launch finds first, and the
//! DLLs of every `PATH` directory outside the system and install roots,
//! where the search ends, except those the system directories already hold,
//! which the loader finds before it reaches `PATH`. Batch
//! files, App Execution Aliases, shims, loader-steering variables and every
//! spelling the two resolvers could read differently stay once-only.

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::os::windows::fs::MetadataExt;
use std::path::Path;

use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
use super::reasons::{Proof, MUTABLE_LAUNCHER, UNPROVEN_LAUNCH};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const MAX_BOUND_FILES: usize = 16;
const MAX_BOUND_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 4096;
/// `PATH` DLLs have their own budget, so a long developer `PATH` neither
/// crowds out the application and working directories nor turns every
/// launch once-only.
const MAX_PATH_DLLS: usize = 128;
const MAX_PATH_DLL_BYTES: u64 = 64 * 1024 * 1024;
/// The system directory an image searches before `PATH`, for each
/// architecture it may run as.
const SYSTEM_DIRS: [&str; 3] = ["System32", "SysWOW64", "SysArm32"];
/// `PATHEXT` as `cmd.exe` defaults it, and the shortcut Cygwin-style shells
/// also start.
const DEFAULT_EXTENSIONS: [&str; 5] = [".com", ".exe", ".bat", ".cmd", ".lnk"];
/// Application-directory files the loader or the .NET host reads for an
/// image (`.json` covers `deps`, `runtimeconfig` and `runtimeconfig.dev`).
const APP_DIR_SUFFIXES: [&str; 3] = [".manifest", ".config", ".json"];
/// Files the DLL search or a bare-name child launch reaches in a directory.
const LOADED_SUFFIXES: [&str; 3] = [".dll", ".exe", ".com"];
/// Variables that load a profiler, startup hook, plugin or provider the
/// image itself never names (matched as uppercase prefixes).
const LOADER_ENVIRONMENT: [&str; 8] = [
    "COR_ENABLE_PROFILING",
    "COR_PROFILER",
    "CORECLR_",
    "DOTNET_STARTUP_HOOKS",
    "DOTNET_ROOT",
    "DOTNET_ADDITIONAL_DEPS",
    "QT_PLUGIN_PATH",
    "OPENSSL_MODULES",
];
/// `PATH` directories inside the Windows directory that only administrators
/// can write; any other one there (`Temp`, `System32\Tasks`) is scanned.
const SYSTEM_PATH_DIRS: [&str; 6] = [
    "",
    "System32",
    "SysWOW64",
    "System32\\Wbem",
    "System32\\WindowsPowerShell\\v1.0",
    "System32\\OpenSSH",
];

/// Whether the harness runs `tool_name` commands through a POSIX shell. Codex
/// and any `PowerShell` tool run PowerShell, whose aliases, profiles and
/// parsing this proof does not model.
pub(super) fn runs_posix_shell(harness: &str, tool_name: &str) -> bool {
    matches!(
        (harness, tool_name),
        ("claude-code", "Bash") | ("omp" | "oh-my-pi" | "pi", "bash")
    )
}

/// The value of a case-insensitive environment variable; two spellings of one
/// name leave which value a child sees undecided.
pub(super) fn env_value<'a>(
    env: &'a BTreeMap<String, String>,
    name: &str,
) -> Proof<Option<&'a str>> {
    let mut found = env.iter().filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let first = found.next().map(|(_, value)| value.as_str());
    if found.next().is_some() {
        return Err(UNPROVEN_LAUNCH);
    }
    Ok(first)
}

/// Inside a Program Files directory as the system reports it, never as the
/// requesting environment spells it; a spelling that could leave the root
/// (`C:\Program Files\..\Users`) is never inside.
pub(super) fn under_install_root(path: &str) -> bool {
    fs_path::is_literal(path)
        && guard_runtime_windows_process::trusted_install_roots()
            .iter()
            .filter_map(|root| root.to_str())
            .map(|root| root.trim_end_matches('\\'))
            .any(|root| {
                path.get(..root.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(root))
                    && path[root.len()..].starts_with('\\')
            })
}

/// The lowercased file stem of the bound image.
pub(super) fn image_stem(identity: &Value) -> String {
    let name = identity["executable"]["path"]
        .as_str()
        .map(fs_path::name)
        .unwrap_or_default()
        .to_ascii_lowercase();
    match name.rsplit_once('.') {
        Some((stem, _)) => stem.to_owned(),
        None => name,
    }
}

/// The engine's launch identity of a native image, with the loader inputs
/// bound as its entrypoint, or why the launch stays once-only.
pub(super) fn native_launch(
    mut identity: Value,
    command: &str,
    cwd: &str,
    ctx: &Ctx,
) -> Proof<Value> {
    let executable = &identity["executable"];
    let verified = executable["status"] == "verified"
        && executable["file_format"] == "native"
        && executable["size"].as_u64().is_some_and(|size| size > 0)
        && executable.get("reuse_nonce").is_none();
    let (Some(image), Some(launch_path)) = (
        executable["path"].as_str().map(str::to_owned),
        executable["launch_path"].as_str().map(str::to_owned),
    ) else {
        return Err(UNPROVEN_LAUNCH);
    };
    if !verified || !spelling_is_pinned(command) || steers_loader(ctx) {
        return Err(UNPROVEN_LAUNCH);
    }
    let image_dir = plain_file(&image, &launch_path)?;
    let image_name = fs_path::name(&image).to_ascii_lowercase();
    let spelled = fs_path::name(command).to_ascii_lowercase();
    // Bash appends only `.exe` to a name, so a `.com` hit is Guard's alone.
    if image_name != spelled && image_name != format!("{spelled}.exe") {
        return Err(UNPROVEN_LAUNCH);
    }
    let stem = image_stem(&identity);
    if fs_path::is_file(&fs_path::join(&image_dir, &format!("{stem}.shim"))) {
        return Err(MUTABLE_LAUNCHER);
    }
    resolvers_agree(command, &image_dir, &image_name, cwd, ctx)?;
    let mut budget = Budget::new(MAX_BOUND_FILES, MAX_BOUND_BYTES);
    let (location, app_dir) = if under_install_root(&image) {
        ("install-root", Value::Null)
    } else {
        let files = bound_files(
            &image_dir,
            Some(&image_name),
            &LOADED_SUFFIXES,
            &|_| false,
            &mut budget,
            ctx,
        )?;
        ("content-bound", json!(files))
    };
    let cwd_dlls = bound_files(cwd, None, &LOADED_SUFFIXES, &|_| false, &mut budget, ctx)?;
    let path_dlls = search_path_dlls(ctx)?;
    identity["entrypoint"] = json!({
        "kind": "windows-native-image",
        "status": "bound-by-executable",
        "location": location,
        "app_dir": app_dir,
        "cwd_dlls": cwd_dlls,
        "path_dlls": path_dlls,
    });
    if carries_reuse_nonce(&identity) {
        return Err(UNPROVEN_LAUNCH);
    }
    Ok(identity)
}

fn steers_loader(ctx: &Ctx) -> bool {
    ctx.env.keys().any(|name| {
        let name = name.to_ascii_uppercase();
        LOADER_ENVIRONMENT
            .iter()
            .any(|prefix| name.starts_with(prefix))
    })
}

/// Content digests of the DLLs in each `PATH` directory, where the loader
/// search ends, and in each `~/bin` Git Bash puts ahead of it, outside the
/// Windows and install roots. A missing directory binds as empty, so a DLL
/// planted in it later changes the token; over the caps stays once-only. A
/// directory listed twice binds once, and a DLL every image finds in a system
/// directory first is never loaded from here, so neither spends the budget.
fn search_path_dlls(ctx: &Ctx) -> Proof<BTreeMap<String, String>> {
    let windows = guard_runtime_windows_process::windows_directory()
        .and_then(|path| path.to_str().map(str::to_owned))
        .ok_or(UNPROVEN_LAUNCH)?;
    let path = env_value(ctx.env, "PATH")?.ok_or(UNPROVEN_LAUNCH)?;
    let (_, homes) = super::git_windows::user_config_roots(ctx)?;
    let homes = homes.iter().map(|home| fs_path::join(home, "bin"));
    let mut budget = Budget::new(MAX_PATH_DLLS, MAX_PATH_DLL_BYTES);
    let mut seen = BTreeSet::new();
    let shadowed = |name: &str| found_before_path(&windows, name);
    let mut found = BTreeMap::new();
    for entry in path.split(';').map(str::to_owned).chain(homes) {
        ctx.check()?;
        if entry.is_empty() {
            continue;
        }
        if entry.contains('"') || !fs_path::is_abs(&entry) {
            return Err(UNPROVEN_LAUNCH);
        }
        // Compare where the entry leads, never how it is spelled. A mapped
        // drive canonicalizes to UNC, which this proof does not store, and an
        // offline share cannot be canonicalized. Bind the folded spelling
        // then. Only a resolved path may skip the system and install roots,
        // so an unresolved spelling cannot hide a directory by naming one.
        let resolved = fs_path::resolve(&entry);
        let entry = resolved.clone().unwrap_or_else(|| fs_path::norm(&entry));
        let system = SYSTEM_PATH_DIRS
            .iter()
            .any(|dir| fs_path::join(&windows, dir).eq_ignore_ascii_case(&entry));
        if resolved.is_some() && (system || under_install_root(&entry)) {
            continue;
        }
        if !seen.insert(entry.to_ascii_lowercase()) {
            continue;
        }
        if fs_path::is_dir(&entry) {
            let dlls = bound_files(&entry, None, &[".dll"], &shadowed, &mut budget, ctx)?;
            found.extend(dlls);
        } else if std::fs::symlink_metadata(&entry).is_ok() {
            return Err(UNPROVEN_LAUNCH);
        }
    }
    Ok(found)
}

/// Whether every image finds a DLL named `name` before the search reaches
/// `PATH`: in the Windows directory, or in every architecture's system
/// directory as only a 64-bit process sees them unredirected. Each search
/// order that reaches `PATH` visits these first; `LOAD_LIBRARY_SEARCH_*` never.
fn found_before_path(windows: &str, name: &str) -> bool {
    let holds = |dir: &str| fs_path::is_file(&fs_path::join(dir, name));
    if holds(windows) {
        return true;
    }
    let mut present = SYSTEM_DIRS
        .iter()
        .map(|dir| fs_path::join(windows, dir))
        .filter(|dir| fs_path::is_dir(dir))
        .peekable();
    cfg!(target_pointer_width = "64") && present.peek().is_some() && present.all(|dir| holds(&dir))
}

/// A spelling bash and `CreateProcessW` read as the same file: no MSYS root
/// (`/usr/bin/git`), rooted, UNC or drive-relative path, no stream, wildcard,
/// `..` (Windows folds it lexically, bash after following links) or
/// component Windows trims (`tool.exe.`).
fn spelling_is_pinned(command: &str) -> bool {
    if command.is_empty() || command.starts_with(['/', '\\', '~']) {
        return false;
    }
    let bytes = command.as_bytes();
    let drive = bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    let rest = if drive { &command[3..] } else { command };
    !rest
        .chars()
        .any(|character| character < ' ' || "<>:\"|?*[".contains(character))
        && rest
            .split(['/', '\\'])
            .all(|part| part == "." || (!part.is_empty() && !part.ends_with(['.', ' '])))
}

/// The directory of a launch path that is a plain file, not a link or an App
/// Execution Alias, and names the bound image under its own name.
fn plain_file(image: &str, launch_path: &str) -> Proof<String> {
    let attributes = std::fs::symlink_metadata(launch_path)
        .map_err(|_| UNPROVEN_LAUNCH)?
        .file_attributes();
    let through_store = [image, launch_path].iter().any(|path| {
        path.split(['\\', '/'])
            .any(|part| part.eq_ignore_ascii_case("WindowsApps"))
    });
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || through_store {
        return Err(UNPROVEN_LAUNCH);
    }
    let image_dir = fs_path::parent(image);
    let launch_dir =
        fs_path::resolve_strict(&fs_path::parent(launch_path)).ok_or(UNPROVEN_LAUNCH)?;
    if !launch_dir.eq_ignore_ascii_case(&image_dir)
        || !fs_path::name(launch_path).eq_ignore_ascii_case(&fs_path::name(image))
    {
        return Err(UNPROVEN_LAUNCH);
    }
    Ok(image_dir)
}

/// Bash and Guard start the same file: the first directory holding any
/// launchable spelling of the name holds only the bound image. Git Bash puts
/// `~/bin` ahead of `PATH`, so a spelling there must be the image too.
fn resolvers_agree(
    command: &str,
    image_dir: &str,
    image_name: &str,
    cwd: &str,
    ctx: &Ctx,
) -> Proof<()> {
    let extensions = launch_extensions(ctx)?;
    let holds_only_image = |dir: &str, name: &str| -> Proof<Option<bool>> {
        let present = launchable_entries(dir, name, &extensions)?;
        if present.is_empty() {
            return Ok(None);
        }
        let resolved = fs_path::resolve_strict(dir).ok_or(UNPROVEN_LAUNCH)?;
        Ok(Some(
            resolved.eq_ignore_ascii_case(image_dir) && present == [image_name],
        ))
    };
    if command.contains(['/', '\\']) {
        let spelled = fs_path::join(cwd, command);
        let found = holds_only_image(&fs_path::parent(&spelled), &fs_path::name(&spelled))?;
        return found
            .filter(|only| *only)
            .map(|_| ())
            .ok_or(UNPROVEN_LAUNCH);
    }
    let (_, homes) = super::git_windows::user_config_roots(ctx)?;
    for home in homes {
        if holds_only_image(&fs_path::join(&home, "bin"), command)? == Some(false) {
            return Err(UNPROVEN_LAUNCH);
        }
    }
    let path = env_value(ctx.env, "PATH")?.ok_or(UNPROVEN_LAUNCH)?;
    for entry in path.split(';') {
        ctx.check()?;
        // Bash reads an empty entry as the working directory, which Guard
        // never searches; a relative or quoted one resolves differently too.
        if entry.contains('"') || !fs_path::is_abs(entry) {
            return Err(UNPROVEN_LAUNCH);
        }
        match holds_only_image(entry, command)? {
            None => continue,
            Some(true) => return Ok(()),
            Some(false) => return Err(UNPROVEN_LAUNCH),
        }
    }
    Err(UNPROVEN_LAUNCH)
}

/// Every extension either resolver may append: the request's and the
/// resident's `PATHEXT`, the defaults, lowercased.
fn launch_extensions(ctx: &Ctx) -> Proof<Vec<String>> {
    let requested = env_value(ctx.env, "PATHEXT")?.map(str::to_owned);
    let mut found: BTreeSet<String> = DEFAULT_EXTENSIONS
        .iter()
        .map(|ext| (*ext).to_owned())
        .collect();
    for list in [requested, std::env::var("PATHEXT").ok()]
        .into_iter()
        .flatten()
    {
        found.extend(
            list.split(';')
                .map(str::trim)
                .filter(|ext| !ext.is_empty())
                .map(str::to_ascii_lowercase),
        );
    }
    Ok(found.into_iter().collect())
}

/// The lowercased names in `dir`, other than directories, that start `name`.
fn launchable_entries(dir: &str, name: &str, extensions: &[String]) -> Proof<Vec<String>> {
    let mut present = Vec::new();
    let suffixes = std::iter::once("").chain(extensions.iter().map(String::as_str));
    for suffix in suffixes {
        let candidate = format!("{name}{suffix}");
        match std::fs::symlink_metadata(Path::new(dir).join(&candidate)) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => present.push(candidate.to_ascii_lowercase()),
            Err(error)
                if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {}
            Err(_) => return Err(UNPROVEN_LAUNCH),
        }
    }
    present.sort();
    present.dedup();
    Ok(present)
}

struct Budget {
    files: usize,
    bytes: u64,
    max_files: usize,
    max_bytes: u64,
}

impl Budget {
    fn new(max_files: usize, max_bytes: u64) -> Self {
        Self {
            files: 0,
            bytes: 0,
            max_files,
            max_bytes,
        }
    }
}

/// Content digests of the loader inputs in `dir`: its files ending in
/// `suffixes` and, for the application directory of `image_name`, its manifests,
/// `.config` and .NET host files and each private assembly
/// (`<name>\<name>.dll`, `.manifest`).
/// A `<image>.local` redirection is refused, and a name `skip` accepts is
/// never read.
fn bound_files(
    dir: &str,
    image_name: Option<&str>,
    suffixes: &[&str],
    skip: &dyn Fn(&str) -> bool,
    budget: &mut Budget,
    ctx: &Ctx,
) -> Proof<BTreeMap<String, String>> {
    let mut found = BTreeMap::new();
    let entries = std::fs::read_dir(dir).map_err(|_| UNPROVEN_LAUNCH)?;
    for (count, entry) in entries.enumerate() {
        ctx.check()?;
        if count >= MAX_DIRECTORY_ENTRIES {
            return Err(UNPROVEN_LAUNCH);
        }
        let entry = entry.map_err(|_| UNPROVEN_LAUNCH)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| UNPROVEN_LAUNCH)?;
        let lowered = name.to_ascii_lowercase();
        let path = fs_path::join(dir, &name);
        let is_dir = entry.file_type().map_err(|_| UNPROVEN_LAUNCH)?.is_dir();
        match image_name {
            Some(image) if lowered == format!("{image}.local") => return Err(UNPROVEN_LAUNCH),
            Some(_) if is_dir => {
                for suffix in [".dll", ".manifest"] {
                    let assembly = fs_path::join(&path, &format!("{name}{suffix}"));
                    if std::fs::symlink_metadata(&assembly).is_ok() {
                        bind(&assembly, budget, &mut found)?;
                    }
                }
            }
            _ if is_dir => {}
            Some(_)
                if APP_DIR_SUFFIXES
                    .iter()
                    .any(|suffix| lowered.ends_with(suffix)) =>
            {
                bind(&path, budget, &mut found)?;
            }
            _ if suffixes.iter().any(|suffix| lowered.ends_with(suffix)) && !skip(&name) => {
                bind(&path, budget, &mut found)?
            }
            _ => {}
        }
    }
    Ok(found)
}

fn bind(path: &str, budget: &mut Budget, found: &mut BTreeMap<String, String>) -> Proof<()> {
    let remaining = budget.max_bytes - budget.bytes;
    budget.files += 1;
    if budget.files > budget.max_files {
        return Err(UNPROVEN_LAUNCH);
    }
    let data = fs_path::read_bounded(path, remaining).ok_or(UNPROVEN_LAUNCH)?;
    budget.bytes += data.len() as u64;
    found.insert(path.to_owned(), fs_path::sha256_hex(&data));
    Ok(())
}

fn carries_reuse_nonce(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key("reuse_nonce") || map.values().any(carries_reuse_nonce)
        }
        Value::Array(items) => items.iter().any(carries_reuse_nonce),
        _ => false,
    }
}
