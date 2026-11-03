//! Bounded folder listing for the dashboard's project picker.
//!
//! Only names, kinds and sizes leave this module; no file is opened. Folders
//! and files are screened with the same credential and link rules a CIGAR
//! source grant applies, so the picker never offers a pick the grant refuses.
//! A listing grants nothing: the grant re-validates every path on its own.
use guard_secure_fs::{
    classify_source_path, contains_symlink_component, credential_directory_path,
    credential_named_path,
};
use serde_json::{json, Map, Value};
use std::fs::{self, DirEntry};
use std::path::{Component, Path, PathBuf};

const SCHEMA: &str = "guard-context-folders.v1";
const MAX_ENTRIES: usize = 400;
/// Directory entries read before sorting. A folder larger than this is shown
/// in part, marked truncated, instead of costing the daemon unbounded memory.
const MAX_SCANNED: usize = 4096;
const MAX_FILE_BYTES: u64 = 65_536;
const MAX_SUGGESTED: usize = 8;
const MAX_PATH: usize = 4096;
const MAX_RELATIVE: usize = 1024;
const PROJECT_MARKERS: [&str; 14] = [
    ".git",
    ".hg",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
    "deno.json",
    "Package.swift",
    "mix.exs",
];
const PLACES: [&str; 14] = [
    "Desktop",
    "Documents",
    "Developer",
    "Projects",
    "projects",
    "code",
    "Code",
    "dev",
    "src",
    "repos",
    "git",
    "GitHub",
    "Documents/GitHub",
    "workspace",
];
const NOISE_DIRS: [&str; 2] = ["node_modules", "__pycache__"];
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "icns", "bmp", "tiff", "svgz", "pdf", "zip", "gz",
    "tgz", "bz2", "xz", "7z", "rar", "tar", "jar", "war", "exe", "dll", "so", "dylib", "a", "o",
    "obj", "class", "wasm", "bin", "dat", "db", "sqlite", "sqlite3", "mp3", "mp4", "mov", "avi",
    "wav", "flac", "ogg", "woff", "woff2", "ttf", "otf", "eot", "psd", "sketch", "fig", "dmg",
    "pkg", "msi", "iso", "lock",
];
const SUGGESTED_NAMES: [&str; 11] = [
    "README.md",
    "README",
    "README.txt",
    "README.rst",
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "ARCHITECTURE.md",
    "DESIGN.md",
    "docs/README.md",
    "docs/index.md",
];

fn fail(code: &str) -> String {
    format!("native_context_assistance_folder_{code}")
}

/// Answers one picker request: `{mode: "folders", path?, hidden?}` or
/// `{mode: "files", workspace, path?}`.
pub(crate) fn browse(input: &Value) -> Result<Value, String> {
    let input = input.as_object().ok_or_else(|| fail("input_invalid"))?;
    if input
        .keys()
        .any(|key| !matches!(key.as_str(), "mode" | "path" | "hidden" | "workspace"))
    {
        return Err(fail("input_invalid"));
    }
    match input.get("mode").map(Value::as_str) {
        None | Some(Some("folders")) => list_folders(input),
        Some(Some("files")) => list_files(input),
        _ => Err(fail("input_invalid")),
    }
}

fn text<'a>(input: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, String> {
    match input.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if value.is_empty() => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(fail("input_invalid")),
    }
}

fn home() -> Result<PathBuf, String> {
    crate::claude_hook_bridge::home_directory().ok_or_else(|| fail("not_found"))
}

/// The path without Windows' `\\?\` prefix, as people and grants spell it.
fn plain(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.as_os_str().to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}").into();
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return rest.into();
        }
    }
    path
}

fn resolve_directory(raw: Option<&str>) -> Result<PathBuf, String> {
    let candidate = match raw.map(str::trim) {
        None | Some("") => home()?,
        Some(raw) if raw.len() > MAX_PATH || raw.contains('\0') => {
            return Err(fail("input_invalid"))
        }
        Some("~") => home()?,
        Some(raw) => match raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
            Some(rest) => home()?.join(rest),
            None => PathBuf::from(raw),
        },
    };
    if !candidate.is_absolute() {
        return Err(fail("not_absolute"));
    }
    let resolved = plain(fs::canonicalize(&candidate).map_err(|_| fail("not_found"))?);
    if !resolved.is_dir() {
        return Err(fail("not_directory"));
    }
    Ok(resolved)
}

fn scan(directory: &Path) -> Result<(Vec<DirEntry>, bool), String> {
    let reader = fs::read_dir(directory).map_err(|error| match error.kind() {
        std::io::ErrorKind::PermissionDenied => fail("denied"),
        _ => fail("unreadable"),
    })?;
    let mut entries: Vec<DirEntry> = reader.flatten().take(MAX_SCANNED + 1).collect();
    let cut = entries.len() > MAX_SCANNED;
    entries.truncate(MAX_SCANNED);
    entries.sort_by_cached_key(|entry| {
        let name = entry.file_name().to_string_lossy().into_owned();
        (name.to_lowercase(), name)
    });
    Ok((entries, cut))
}

fn name_of(entry: &DirEntry) -> String {
    entry.file_name().to_string_lossy().into_owned()
}

/// A real folder, never a link or junction to one.
fn plain_folder(entry: &DirEntry) -> bool {
    entry
        .file_type()
        .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
        && !reparse_point(entry)
}

#[cfg(windows)]
fn reparse_point(entry: &DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;
    entry
        .metadata()
        .is_ok_and(|metadata| metadata.file_attributes() & 0x400 != 0)
}

#[cfg(not(windows))]
fn reparse_point(_entry: &DirEntry) -> bool {
    false
}

fn hidden(entry: &DirEntry) -> bool {
    entry.file_name().to_string_lossy().starts_with('.') || system_hidden(entry)
}

/// Hidden or system, as Explorer hides them.
#[cfg(windows)]
fn system_hidden(entry: &DirEntry) -> bool {
    use std::os::windows::fs::MetadataExt;
    entry
        .metadata()
        .is_ok_and(|metadata| metadata.file_attributes() & 0x6 != 0)
}

#[cfg(not(windows))]
fn system_hidden(_entry: &DirEntry) -> bool {
    false
}

fn is_project(path: &Path) -> bool {
    PROJECT_MARKERS
        .iter()
        .any(|marker| fs::symlink_metadata(path.join(marker)).is_ok())
}

fn places(home: &Path) -> Vec<Value> {
    let mut seen = vec![home.to_path_buf()];
    let mut places = vec![json!({"label":"Home", "path":home, "kind":"home"})];
    for name in PLACES {
        let candidate = home.join(name);
        if contains_symlink_component(&candidate) || !candidate.is_dir() {
            continue;
        }
        let Ok(resolved) = fs::canonicalize(&candidate).map(plain) else {
            continue;
        };
        if seen.iter().any(|known| same_path(known, &resolved)) {
            continue;
        }
        seen.push(resolved.clone());
        let label = name.rsplit('/').next().unwrap_or(name);
        places.push(json!({"label":label, "path":resolved, "kind":"folder"}));
    }
    places
}

/// Case-insensitive on Windows and macOS, where `Code` and `code` are one folder.
fn same_path(left: &Path, right: &Path) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase()
    } else {
        left == right
    }
}

fn roots() -> Vec<Value> {
    if cfg!(windows) {
        (b'A'..=b'Z')
            .map(char::from)
            .filter(|letter| Path::new(&format!("{letter}:\\")).is_dir())
            .map(
                |letter| json!({"label":format!("{letter}: drive"), "path":format!("{letter}:\\")}),
            )
            .collect()
    } else {
        vec![json!({"label":"This computer", "path":"/"})]
    }
}

fn list_folders(input: &Map<String, Value>) -> Result<Value, String> {
    let directory = resolve_directory(text(input, "path")?)?;
    let show_hidden = match input.get("hidden") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return Err(fail("input_invalid")),
    };
    let home = home()?;
    let (scanned, mut truncated) = scan(&directory)?;
    let mut entries = Vec::new();
    for entry in scanned {
        if !plain_folder(&entry)
            || (!show_hidden && hidden(&entry))
            || credential_directory_path(&entry.path())
        {
            continue;
        }
        if entries.len() == MAX_ENTRIES {
            truncated = true;
            break;
        }
        let path = plain(entry.path());
        entries.push(json!({"name":name_of(&entry), "project":is_project(&path), "path":path}));
    }
    let parent = directory.parent().filter(|parent| *parent != directory);
    let name = directory.file_name().map_or_else(
        || directory.to_string_lossy(),
        |name| name.to_string_lossy(),
    );
    Ok(json!({
        "schema":SCHEMA, "mode":"folders", "path":directory, "name":name, "parent":parent,
        "project":is_project(&directory), "home":home, "separator":std::path::MAIN_SEPARATOR_STR,
        "places":places(&home), "roots":roots(), "entries":entries, "truncated":truncated,
    }))
}

/// A `/`-separated path inside the project, checked the way grants check it.
fn relative(raw: Option<&str>) -> Result<Vec<String>, String> {
    let Some(raw) = raw
        .map(|raw| raw.trim_matches('/'))
        .filter(|raw| !raw.is_empty())
    else {
        return Ok(Vec::new());
    };
    if raw.len() > MAX_RELATIVE || raw.contains(['\\', ':', '\0']) {
        return Err(fail("input_invalid"));
    }
    let parts: Vec<String> = raw.split('/').map(str::to_owned).collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(fail("input_invalid"));
    }
    Ok(parts)
}

fn join(parts: &[String], name: &str) -> String {
    if parts.is_empty() {
        name.to_owned()
    } else {
        format!("{}/{name}", parts.join("/"))
    }
}

fn file_row(entry: &DirEntry, parts: &[String]) -> Option<Value> {
    let kind = entry.file_type().ok()?;
    if !kind.is_file() || kind.is_symlink() {
        return None;
    }
    let size = entry.metadata().ok()?.len();
    let name = name_of(entry);
    let extension = Path::new(&name)
        .extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let reason = if BINARY_EXTENSIONS.contains(&extension.as_str()) {
        Some("not_text")
    } else if size == 0 {
        Some("empty")
    } else if size > MAX_FILE_BYTES {
        Some("too_large")
    } else {
        None
    };
    Some(
        json!({"name":name, "relative":join(parts, &name), "size":size,
        "available":reason.is_none(), "reason":reason}),
    )
}

/// The screens a source grant and its read apply to one project file.
fn grantable(workspace: &Path, relative: &str) -> bool {
    !credential_named_path(Path::new(relative))
        && !credential_directory_path(Path::new(relative))
        && classify_source_path(relative, workspace, None, false).allowed
}

/// Plain readable files a grant would accept, never reached through a link.
fn suggestible(workspace: &Path, relative: &str) -> Option<u64> {
    let path = workspace.join(relative);
    if contains_symlink_component(&path) || !grantable(workspace, relative) {
        return None;
    }
    let metadata = fs::symlink_metadata(&path).ok()?;
    (metadata.is_file() && (1..=MAX_FILE_BYTES).contains(&metadata.len())).then_some(metadata.len())
}

fn suggested(workspace: &Path) -> Vec<Value> {
    let mut names: Vec<String> = SUGGESTED_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let docs = workspace.join("docs");
    if !contains_symlink_component(&docs) && docs.is_dir() {
        if let Ok((entries, _)) = scan(&docs) {
            names.extend(
                entries
                    .iter()
                    .map(name_of)
                    .filter(|name| name.to_lowercase().ends_with(".md"))
                    .map(|name| format!("docs/{name}")),
            );
        }
    }
    let mut seen: Vec<String> = Vec::new();
    let mut picks = Vec::new();
    for relative in names {
        let key = relative.to_lowercase();
        if picks.len() == MAX_SUGGESTED || seen.contains(&key) {
            continue;
        }
        if let Some(size) = suggestible(workspace, &relative) {
            seen.push(key);
            picks.push(json!({"relative":relative, "size":size}));
        }
    }
    picks
}

fn list_files(input: &Map<String, Value>) -> Result<Value, String> {
    let raw = text(input, "workspace")?.ok_or_else(|| fail("input_invalid"))?;
    let workspace = resolve_directory(Some(raw))?;
    let parts = relative(text(input, "path")?)?;
    let directory = parts
        .iter()
        .fold(workspace.clone(), |path, part| path.join(part));
    // No link anywhere below the project: a linked folder could lead outside it.
    let inside = directory.strip_prefix(&workspace).is_ok_and(|rest| {
        rest.components()
            .all(|part| matches!(part, Component::Normal(_)))
    });
    if !inside || contains_symlink_component(&directory) || !directory.is_dir() {
        return Err(fail("not_found"));
    }
    let (scanned, mut truncated) = scan(&directory)?;
    let (mut folders, mut files) = (Vec::new(), Vec::new());
    for entry in scanned {
        let name = name_of(&entry);
        if hidden(&entry) || NOISE_DIRS.contains(&name.as_str()) {
            continue;
        }
        if folders.len() + files.len() == MAX_ENTRIES {
            truncated = true;
            break;
        }
        let relative = join(&parts, &name);
        if plain_folder(&entry) {
            if !credential_directory_path(Path::new(&relative)) {
                folders.push(json!({"name":name, "relative":relative}));
            }
        } else if grantable(&workspace, &relative) {
            files.extend(file_row(&entry, &parts));
        }
    }
    let at_top = parts.is_empty();
    Ok(json!({
        "schema":SCHEMA, "mode":"files", "workspace":workspace, "path":parts.join("/"),
        "entries":folders, "files":files,
        "suggested":if at_top { suggested(&workspace) } else { Vec::new() },
        "max_file_bytes":MAX_FILE_BYTES, "truncated":truncated,
    }))
}

#[cfg(test)]
#[path = "context_assistance_folders_tests.rs"]
mod tests;
