//! The output directory a project's Vite config names, when it is a literal path.
//!
//! Projects often build into a directory other than `dist`, such as a static
//! folder another package serves. The build-output profile may write there
//! only when the config spells the directory as a literal (optionally through
//! `resolve(__dirname, ...)` or `join(__dirname, ...)`), it stays inside the
//! workspace, and it does not cover the package's own sources.
//!
//! The grammar and the admissibility walk live here once. The package-script
//! sink asks whether the build it is about to admit would find a verifiable
//! output, and the contained Node tool asks for the directory itself; both
//! read the same answer, so neither can drift from the other.

use serde_json::{json, Value};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_EXISTING_FILES: usize = 20_000;
const CONFIG_NAMES: [&str; 6] = [
    "vite.config.ts",
    "vite.config.mts",
    "vite.config.cts",
    "vite.config.js",
    "vite.config.mjs",
    "vite.config.cjs",
];
const ASSETS: &[&str] = &[
    "avif",
    "br",
    "css",
    "eot",
    "gif",
    "gz",
    "htm",
    "html",
    "ico",
    "jpeg",
    "jpg",
    "js",
    "json",
    "map",
    "mjs",
    "mp3",
    "mp4",
    "otf",
    "png",
    "svg",
    "ttf",
    "txt",
    "wasm",
    "wav",
    "webm",
    "webmanifest",
    "webp",
    "woff",
    "woff2",
    "xml",
];

/// What a run directory's Vite config says about where the build writes.
#[derive(Debug, PartialEq, Eq)]
pub enum Declared {
    /// No config, several of them, or one that never mentions `outDir`: the
    /// build writes wherever the command and Vite's own default put it.
    Default,
    /// The one directory the config names, admissible as a build target.
    Output(PathBuf),
    /// The config names an output this cannot verify inside the project, so
    /// the build is refused with a reason rather than a denied write.
    Unverified,
}

fn out_dir_patterns() -> (&'static Regex, &'static Regex) {
    static MENTIONS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\boutDir\b").expect("outDir mention"));
    static LITERAL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"(?x)
            \boutDir\s*:\s*(?:
                (?:path\.)?(?:resolve|join)\(\s*__dirname\s*,\s*['"]([^'"\\$`]+)['"]\s*\)
                | ['"]([^'"\\$`]+)['"]
            )
            "#,
        )
        .expect("vite outDir literal")
    });
    (&MENTIONS, &LITERAL)
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

/// The config the command loads, or `None` when nothing names one directory.
///
/// `config` is the file named by `--config`. When the command names one, that
/// file is the config Vite will load, so the default `vite.config.*` beside it
/// is not a substitute, and a missing file leaves the output to `--outDir` or
/// `dist`. Without one, exactly one conventional name must sit in the run
/// directory; several configs leave the output to the build's own default.
fn chosen_config(cwd: &Path, workspace: &Path, config: Option<&Path>) -> Result<PathBuf, Declared> {
    let Some(named) = config else {
        let mut found = CONFIG_NAMES
            .iter()
            .map(|name| cwd.join(name))
            .filter(|path| path.is_file());
        let (Some(path), None) = (found.next(), found.next()) else {
            return Err(Declared::Default);
        };
        if is_symlink(&path) {
            return Err(Declared::Default);
        }
        return Ok(path);
    };
    // The named config is judged by where it resolves, not by how it is
    // spelled. A `..` component, or a parent reached through a link, lands
    // outside the workspace while the spelling still opens with it, and this
    // file is read here before the build runs. Resolving the directory also
    // settles the config's own spelling, so an `outDir` read relative to it
    // cannot carry a parent component into the admissibility walk.
    let (Some(parent), Some(name)) = (named.parent(), named.file_name()) else {
        return Err(Declared::Unverified);
    };
    let (Ok(parent), Ok(root)) = (parent.canonicalize(), workspace.canonicalize()) else {
        // A directory that does not resolve names no config in the workspace,
        // so nothing here can say the build's output is the default one.
        return Err(Declared::Unverified);
    };
    let Ok(inside) = parent.strip_prefix(&root) else {
        return Err(Declared::Unverified);
    };
    // The resolved directory is spelled back under the workspace the caller
    // holds, so the admissibility walk below reads the prefix it was handed
    // rather than a second spelling of the same directory: resolving a path
    // under the system temporary directory answers `/private/var/...` where
    // the caller holds `/var/...`, and both name one place.
    let resolved = workspace.join(inside).join(name);
    if !resolved.is_file() || is_symlink(&resolved) {
        return Err(Declared::Default);
    }
    Ok(resolved)
}

/// The config's literal output directory, read once for every caller.
pub fn declared_output(cwd: &Path, workspace: &Path, config: Option<&Path>) -> Declared {
    let path = match chosen_config(cwd, workspace, config) {
        Ok(path) => path,
        Err(answer) => return answer,
    };
    // One byte past the limit is enough to know the config is over it, so an
    // oversized file is never decoded, scanned or captured from: the work the
    // resident does on the hook path is bounded by the limit rather than by
    // the size of a file the workspace supplies.
    let Ok(file) = std::fs::File::open(&path) else {
        return Declared::Default;
    };
    let mut raw = Vec::new();
    if file
        .take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .is_err()
    {
        return Declared::Default;
    }
    if raw.len() > MAX_CONFIG_BYTES {
        return Declared::Unverified;
    }
    let text = String::from_utf8_lossy(&raw);
    let (mentions, literal) = out_dir_patterns();
    let mention_count = mentions.find_iter(&text).count();
    if mention_count == 0 {
        return Declared::Default;
    }
    let captures: Vec<_> = literal.captures_iter(&text).collect();
    if mention_count != 1 || captures.len() != 1 {
        return Declared::Unverified;
    }
    let Some(spelled) = captures[0]
        .get(1)
        .or_else(|| captures[0].get(2))
        .map(|value| value.as_str())
    else {
        return Declared::Unverified;
    };
    // `__dirname` is the config file's directory. A named config may not sit
    // in the run directory, and Vite resolves a literal `outDir` from the file
    // that declares it.
    let base = path.parent().unwrap_or(cwd);
    let output = config_output_path(base, spelled);
    if declared_output_is_admissible(&output, cwd, workspace) {
        Declared::Output(output)
    } else {
        Declared::Unverified
    }
}

/// Whether the package-script sink would admit the build this config declares.
///
/// A config that names nothing keeps the sink's own default, so only an
/// unverifiable declaration refuses the build here.
pub fn config_output_is_verifiable(directory: &Path, workspace: &Path) -> bool {
    declared_output(directory, workspace, None) != Declared::Unverified
}

fn config_output_path(directory: &Path, spelled: &str) -> PathBuf {
    let spelled = Path::new(spelled);
    if spelled.is_absolute() {
        return spelled.to_path_buf();
    }
    let mut output = directory.to_path_buf();
    for part in spelled.components() {
        match part {
            Component::ParentDir => {
                output.pop();
            }
            Component::CurDir => {}
            Component::Normal(name) => output.push(name),
            Component::RootDir | Component::Prefix(_) => return spelled.to_path_buf(),
        }
    }
    output
}

/// Inside the workspace, not the workspace or the run directory, no hidden or
/// `node_modules` part, no link or package manifest along the path, and an
/// existing directory holds only built assets.
fn declared_output_is_admissible(output: &Path, directory: &Path, workspace: &Path) -> bool {
    if output == workspace || output == directory || directory.starts_with(output) {
        return false;
    }
    let Ok(relative) = output.strip_prefix(workspace) else {
        return false;
    };
    if relative.as_os_str().is_empty() {
        return false;
    }
    let mut reached = workspace.to_path_buf();
    for part in relative.components() {
        let name = part.as_os_str().to_string_lossy();
        if name.starts_with('.') || name == "node_modules" {
            return false;
        }
        reached.push(part);
        if let Ok(metadata) = std::fs::symlink_metadata(&reached) {
            let kind = metadata.file_type();
            if kind.is_symlink() || !kind.is_dir() {
                return false;
            }
        }
        if reached.join("package.json").exists() {
            return false;
        }
    }
    built_assets_only(output)
}

/// An existing directory the build may empty holds nothing but web assets.
///
/// Vite empties its output first, so a directory holding sources or scripts is
/// never accepted as a build target.
fn built_assets_only(output: &Path) -> bool {
    if !output.exists() {
        return true;
    }
    let mut visited = 0usize;
    let mut pending = vec![output.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return false;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            let Ok(kind) = entry.file_type() else {
                return false;
            };
            // A link to a directory is listed as a directory and not descended
            // into. A link to a file is a file.
            if kind.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if kind.is_symlink() && entry.path().is_dir() {
                continue;
            }
            visited += 1;
            if visited > MAX_EXISTING_FILES {
                return false;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "package.json" {
                return false;
            }
            if name == ".gitkeep" || name == ".DS_Store" {
                continue;
            }
            let Some(extension) = Path::new(name.as_ref()).extension() else {
                return false;
            };
            let extension = extension.to_string_lossy().to_lowercase();
            if !ASSETS.contains(&extension.as_str()) {
                return false;
            }
        }
    }
    true
}

/// Where Vite's default loader writes the bundled config, when Guard can
/// grant it.
///
/// Vite bundles `vite.config.ts` into `node_modules/.vite-temp` next to the
/// config, imports that one file and deletes it. Granting that directory lets
/// configs that use `__dirname` load as they do outside Guard. Nothing keeps
/// the write-free runner loader.
pub fn bundle_directory(cwd: &Path, workspace: &Path, modules: &Path) -> Option<PathBuf> {
    let nearest = cwd
        .ancestors()
        .map(|directory| directory.join("node_modules"))
        .find(|candidate| candidate.exists())?;
    // The nearest `node_modules` and the one the caller asks to grant are the
    // same directory when they resolve to one place, and the workspace holds
    // it when the resolved directory sits below the resolved workspace. The
    // replaced reader compared resolved paths too, and on Windows that
    // comparison ignored case, so a directory spelled with different
    // capitalization than the workspace still named the project's own.
    let (Ok(reached), Ok(asked), Ok(root)) = (
        nearest.canonicalize(),
        modules.canonicalize(),
        workspace.canonicalize(),
    ) else {
        return None;
    };
    if reached != asked || !reached.starts_with(&root) {
        return None;
    }
    // The climb ends on the resolved workspace, because the spelling it was
    // asked about need not be the one `cwd` carries: a link stands above both
    // in `/tmp` against `/private/tmp`, and Windows spells the same directory
    // in either case. Comparing the written spellings there would walk past
    // the workspace to the filesystem root and refuse the project's own
    // `node_modules`, which is the grant this reader exists to make. Each
    // step is still read as it was written, so a link standing between the
    // two is refused rather than followed.
    let mut current = nearest.as_path();
    while current.canonicalize().ok()? != root {
        if is_symlink(current) {
            return None;
        }
        current = current.parent()?;
    }
    let temp = nearest.join(".vite-temp");
    if is_symlink(&nearest) || !nearest.is_dir() || is_symlink(&temp) {
        return None;
    }
    if temp.exists() {
        if !temp.is_dir() {
            return None;
        }
        let entries = std::fs::read_dir(&temp).ok()?;
        let mut seen = 0usize;
        for entry in entries {
            let entry = entry.ok()?;
            seen += 1;
            if seen > 256 || !entry.file_type().ok()?.is_file() {
                return None;
            }
        }
    }
    Some(temp)
}

fn requested_path(input: &Value, field: &str) -> Option<PathBuf> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// `vite_declared_output` answers the directory, or nothing, or the refusal
/// the build reports instead of failing on a denied write.
/// `vite_bundle_directory` answers the config loader's own writable
/// directory, or nothing when the write-free loader stands.
///
/// The request carries the caller's own `cwd` and `workspace` as they were
/// spelled. A request missing either names no project, so it is read as one
/// that declares nothing rather than as a refusal.
pub fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if !matches!(operation, "vite_declared_output" | "vite_bundle_directory") {
        return None;
    }
    let (Some(cwd), Some(workspace)) = (
        requested_path(input, "cwd"),
        requested_path(input, "workspace"),
    ) else {
        return Some(json!({"value": Value::Null}));
    };
    if operation == "vite_bundle_directory" {
        let modules = requested_path(input, "modules").unwrap_or_default();
        let bundle = bundle_directory(&cwd, &workspace, &modules);
        return Some(json!({"value": bundle.map(|path| path.to_string_lossy().into_owned())}));
    }
    Some(
        match declared_output(&cwd, &workspace, requested_path(input, "config").as_deref()) {
            Declared::Default => json!({"value": Value::Null}),
            Declared::Output(output) => json!({"value": output.to_string_lossy()}),
            Declared::Unverified => json!({
                "reason_code": "node_build_invalid_output",
                "message": "The Vite config sets an output directory HOL Guard could not verify inside the project."
            }),
        },
    )
}
