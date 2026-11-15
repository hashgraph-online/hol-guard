//! Where Paseo's daemon keeps its config and Guard its receipt, and the
//! no-redirect rule every Paseo-managed write target passes first.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{path_text, Ctx, Failure, Step};
use crate::pyjson::PyVal;

const MAX_CONFIG_BYTES: u64 = 2 * 1024 * 1024;
const ESCAPES: &str = "Paseo managed path escapes its declared root.";

/// `paseo_config_path(context)`.
pub(crate) fn config_path(ctx: &Ctx) -> Step<PathBuf> {
    let override_home = if ctx.home_explicit {
        ""
    } else {
        ctx.env("PASEO_HOME").unwrap_or_default().trim()
    };
    if override_home.is_empty() {
        return Ok(ctx.home.join(".paseo").join("config.json"));
    }
    let root = match override_home.strip_prefix("~/") {
        _ if override_home == "~" => ctx.home.clone(),
        Some("") => ctx.home.clone(),
        Some(rest) => ctx.home.join(rest),
        None => PathBuf::from(override_home),
    };
    if !root.is_absolute() {
        return Err(Failure::Refusal(
            "Use an absolute PASEO_HOME on the Paseo daemon host.".into(),
        ));
    }
    Ok(root.join("config.json"))
}

/// `os.path.abspath`: anchored on the caller's directory, then normalised
/// without touching the filesystem.
pub(crate) fn abspath(ctx: &Ctx, path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in ctx.absolute(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normal.parent().is_some() {
                    normal.pop();
                }
            }
            other => normal.push(other.as_os_str()),
        }
    }
    normal
}

fn anchor_of(path: &Path) -> PathBuf {
    path.components()
        .take_while(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
        .collect()
}

/// `require_local_path(root, path, home_dir=home)`: no link, special file or
/// multiply-linked file from the trust anchor down to `path`.
pub(crate) fn require_local(ctx: &Ctx, root: &Path, path: &Path, home: Option<&Path>) -> Step<()> {
    let escapes = || Failure::Refusal(ESCAPES.into());
    let mut root = abspath(ctx, root);
    let mut path = abspath(ctx, path);
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| escapes())?
        .to_path_buf();
    let mut anchor = anchor_of(&root);
    if let Some(home) = home {
        let home = abspath(ctx, home);
        if let Ok(below) = root.strip_prefix(&home).map(Path::to_path_buf) {
            anchor = ctx.resolved(&home);
            root = anchor.join(below);
            path = root.join(&relative);
        }
    }
    let rest = path
        .strip_prefix(&anchor)
        .map_err(|_| escapes())?
        .to_path_buf();
    let mut candidate = anchor.clone();
    let mut parts = vec![None];
    parts.extend(rest.components().map(Some));
    for part in parts {
        if let Some(part) = part {
            candidate.push(part.as_os_str());
        }
        let shown = path_text(&candidate);
        let Ok(link) = fs::symlink_metadata(&candidate) else {
            continue;
        };
        if link.file_type().is_symlink() {
            return Err(Failure::Refusal(format!(
                "Paseo refuses a symlink in a managed path: {shown}"
            )));
        }
        if !(link.is_dir() || link.is_file()) {
            return Err(Failure::Refusal(format!(
                "Paseo requires regular managed files: {shown}"
            )));
        }
        if link.is_file() && link_count(&link) != 1 {
            return Err(Failure::Refusal(format!(
                "Paseo refuses a multiply-linked managed file: {shown}"
            )));
        }
    }
    if ctx.resolved(&path).starts_with(ctx.resolved(&root)) {
        Ok(())
    } else {
        Err(escapes())
    }
}

#[cfg(unix)]
fn link_count(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(not(unix))]
fn link_count(_meta: &fs::Metadata) -> u64 {
    1
}

#[cfg(unix)]
fn open_config(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(unix))]
fn open_config(path: &Path) -> std::io::Result<fs::File> {
    fs::File::open(path)
}

fn bounded_read(path: &Path) -> Option<Vec<u8>> {
    if path.is_symlink() {
        return None;
    }
    let mut file = open_config(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let mut content = Vec::new();
    (&mut file)
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut content)
        .ok()?;
    (content.len() as u64 <= MAX_CONFIG_BYTES).then_some(content)
}

/// `read_config_object(path)`: an absent file is empty; anything unsafe or
/// malformed, duplicate keys included, is refused without echoing content.
pub(crate) fn read_config_object(ctx: &Ctx, path: &Path) -> Step<Vec<(String, PyVal)>> {
    let absolute = ctx.absolute(path);
    if !absolute.exists() && !absolute.is_symlink() {
        return Ok(Vec::new());
    }
    let object = bounded_read(&absolute)
        .and_then(|content| String::from_utf8(content).ok())
        .and_then(|text| match crate::pyjson::parse_unique(&text) {
            Ok(PyVal::Dict(entries)) => Some(entries),
            _ => None,
        });
    object.ok_or_else(|| {
        Failure::Refusal(format!(
            "Cannot safely read configuration at {}; repair it before installing Paseo protection.",
            path_text(path)
        ))
    })
}

/// `str(paseo_config_path(context).absolute())`, the receipt's identity.
pub(crate) fn config_identity(ctx: &Ctx) -> Step<String> {
    Ok(path_text(&ctx.absolute(&config_path(ctx)?)))
}

/// `receipt_path(context)`: one receipt per daemon config, checked.
pub(crate) fn receipt_path(ctx: &Ctx) -> Step<PathBuf> {
    let digest = hex::encode(Sha256::digest(config_identity(ctx)?.as_bytes()));
    let path = ctx
        .guard_home
        .join("managed")
        .join("paseo")
        .join(format!("{}.json", &digest[..20]));
    require_local(ctx, &ctx.guard_home, &path, Some(&ctx.home))?;
    Ok(path)
}

/// `Path.rglob("*")` without descending through links, in a stable order.
pub(crate) fn walk(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut entries: Vec<PathBuf> = match fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect(),
        Err(_) => return found,
    };
    entries.sort();
    for entry in entries {
        let descend = fs::symlink_metadata(&entry).is_ok_and(|meta| meta.is_dir());
        found.push(entry.clone());
        if descend {
            found.extend(walk(&entry));
        }
    }
    found
}
