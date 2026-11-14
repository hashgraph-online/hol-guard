//! What the `attest` op expects the interpreter to import, and the neutral
//! directory it runs in, which `_parent_expectation` and `_private_probe_cwd`
//! in `guard/adapters/hook_python.py` derived before they moved here.
//!
//! The parent sends only what Python alone can read: the file its package
//! was imported from, its version, and where `importlib.metadata` locates the
//! `cryptography` and `hol-guard` distributions (`null` when it has none). This decides whether those
//! agree: the `cryptography` package inside its distribution, a `hol-guard`
//! distribution at this version with Guard's entry point that holds the
//! package (or names it as an editable `src` checkout), and the import roots
//! the probe may search.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::resolve;
use crate::claude_hook_bridge_url::py_unquote;
use crate::runner_authority_op::ERR_INVALID;

const ENTRY_POINT: &str = "codex_plugin_scanner.cli:main";
const NEUTRAL_CWD_UNAVAILABLE: &str = "guard_hook_python_neutral_cwd_unavailable";
const PACKAGE_UNAVAILABLE: &str = "guard_hook_python_active_package_unavailable";
const PACKAGE_ROOT_MISMATCH: &str = "guard_hook_python_package_root_mismatch";
const CRYPTOGRAPHY_DISTRIBUTION_UNAVAILABLE: &str =
    "guard_hook_python_cryptography_distribution_unavailable";
const CRYPTOGRAPHY_UNAVAILABLE: &str = "guard_hook_python_cryptography_unavailable";
const CRYPTOGRAPHY_MISMATCH: &str = "guard_hook_python_cryptography_distribution_mismatch";
const HOL_UNAVAILABLE: &str = "guard_hook_python_hol_guard_distribution_unavailable";
const HOL_MISMATCH: &str = "guard_hook_python_hol_guard_distribution_mismatch";

/// The facts the parent sends, read from the request.
pub(super) struct Facts<'a> {
    package_file: &'a Path,
    package_root: Option<&'a Path>,
    version: &'a str,
    cryptography_root: Option<&'a Path>,
    hol: Option<Hol<'a>>,
}

struct Hol<'a> {
    root: &'a Path,
    version: &'a str,
    entry_point: Option<&'a str>,
    direct_url: Option<&'a str>,
}

const FACT_KEYS: [&str; 5] = [
    "package_file",
    "package_root",
    "version",
    "cryptography_root",
    "hol",
];
const HOL_KEYS: [&str; 4] = ["root", "version", "entry_point", "direct_url"];

fn exact<'a>(
    value: Option<&'a Value>,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, &'static str> {
    value
        .and_then(Value::as_object)
        .filter(|map| map.len() == keys.len() && keys.iter().all(|key| map.contains_key(*key)))
        .ok_or(ERR_INVALID)
}

fn absolute(value: Option<&Value>) -> Result<&Path, &'static str> {
    value
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|path| path.is_absolute())
        .ok_or(ERR_INVALID)
}

fn text(value: Option<&Value>) -> Result<&str, &'static str> {
    value.and_then(Value::as_str).ok_or(ERR_INVALID)
}

fn optional<'a, T>(
    value: Option<&'a Value>,
    read: impl FnOnce(Option<&'a Value>) -> Result<T, &'static str>,
) -> Result<Option<T>, &'static str> {
    match value {
        Some(Value::Null) => Ok(None),
        other => read(other).map(Some),
    }
}

impl<'a> Facts<'a> {
    pub(super) fn parse(value: Option<&'a Value>) -> Result<Self, &'static str> {
        let map = exact(value, &FACT_KEYS)?;
        let hol = optional(map.get("hol"), |value| {
            let hol = exact(value, &HOL_KEYS)?;
            Ok(Hol {
                root: absolute(hol.get("root"))?,
                version: text(hol.get("version"))?,
                entry_point: optional(hol.get("entry_point"), text)?,
                direct_url: optional(hol.get("direct_url"), text)?,
            })
        })?;
        Ok(Self {
            package_file: absolute(map.get("package_file"))?,
            package_root: optional(map.get("package_root"), absolute)?,
            version: text(map.get("version"))?,
            cryptography_root: optional(map.get("cryptography_root"), absolute)?,
            hol,
        })
    }
}

/// The record fields the probe must report back.
pub(super) fn expectation(facts: &Facts) -> Result<Map<String, Value>, &'static str> {
    let package_file = resolve(facts.package_file).map_err(|_| PACKAGE_UNAVAILABLE)?;
    let package_root = package_file
        .parent()
        .and_then(Path::parent)
        .filter(|root| root.is_dir())
        .ok_or(PACKAGE_UNAVAILABLE)?
        .to_path_buf();
    let cryptography_root = facts
        .cryptography_root
        .and_then(|root| resolve(root).ok())
        .filter(|root| root.is_dir())
        .ok_or(CRYPTOGRAPHY_DISTRIBUTION_UNAVAILABLE)?;
    let cryptography_file = resolve(&cryptography_root.join("cryptography").join("__init__.py"))
        .map_err(|_| CRYPTOGRAPHY_UNAVAILABLE)?;
    if !cryptography_file.is_file() || !cryptography_file.starts_with(&cryptography_root) {
        return Err(CRYPTOGRAPHY_MISMATCH);
    }
    let hol_root = match &facts.hol {
        None if editable_source_root(&package_root) => None,
        None => return Err(HOL_UNAVAILABLE),
        Some(hol) => Some(distribution(
            hol,
            facts.version,
            &package_file,
            &package_root,
        )?),
    };
    if let Some(expected) = facts.package_root {
        if resolve(expected).ok().as_ref() != Some(&package_root) {
            return Err(PACKAGE_ROOT_MISMATCH);
        }
    }
    let mut roots: Vec<&PathBuf> = Vec::new();
    for root in [
        Some(&package_root),
        hol_root.as_ref(),
        Some(&cryptography_root),
    ]
    .into_iter()
    .flatten()
    {
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    let shown = |path: &Path| path.to_string_lossy().into_owned();
    let mut record = Map::new();
    record.insert("package_file".into(), json!(shown(&package_file)));
    record.insert("package_root".into(), json!(shown(&package_root)));
    record.insert("cryptography_file".into(), json!(shown(&cryptography_file)));
    let roots: Vec<String> = roots.iter().map(|root| shown(root)).collect();
    record.insert("import_roots".into(), json!(roots));
    record.insert(
        "hol_distribution_root".into(),
        json!(hol_root.as_deref().map(shown)),
    );
    record.insert(
        "cryptography_distribution_root".into(),
        json!(shown(&cryptography_root)),
    );
    record.insert("version".into(), json!(facts.version));
    record.insert("entry_point".into(), json!(ENTRY_POINT));
    Ok(record)
}

/// The `hol-guard` distribution root, when it is this version with Guard's
/// entry point and holds the running package or names it as editable.
fn distribution(
    hol: &Hol,
    version: &str,
    package_file: &Path,
    package_root: &Path,
) -> Result<PathBuf, &'static str> {
    let root = resolve(hol.root).map_err(|_| HOL_UNAVAILABLE)?;
    if hol.version != version || hol.entry_point != Some(ENTRY_POINT) {
        return Err(HOL_MISMATCH);
    }
    if !package_file.starts_with(&root) {
        let editable = hol.direct_url.and_then(editable_url_root);
        if editable.map(|source| source.join("src")).as_deref() != Some(package_root)
            || !editable_source_root(package_root)
        {
            return Err(HOL_MISMATCH);
        }
    }
    Ok(root)
}

/// A `src` directory holding the package beside a `pyproject.toml`.
fn editable_source_root(package_root: &Path) -> bool {
    package_root.file_name().is_some_and(|name| name == "src")
        && package_root
            .join("codex_plugin_scanner")
            .join("__init__.py")
            .is_file()
        && package_root
            .parent()
            .is_some_and(|parent| parent.join("pyproject.toml").is_file())
}

/// The directory a PEP 610 `direct_url.json` names for an editable install,
/// when it is a plain local `file:` URL that exists.
fn editable_url_root(direct_url: &str) -> Option<PathBuf> {
    let value: Value = serde_json::from_str(direct_url).ok()?;
    let editable = value
        .get("dir_info")
        .and_then(Value::as_object)?
        .get("editable");
    if editable != Some(&Value::Bool(true)) {
        return None;
    }
    let path = local_file_url_path(value.get("url")?.as_str()?)?;
    resolve(&url_to_path(&py_unquote(&path))).ok()
}

/// The path of a `file:` URL with no host but `localhost` and no
/// parameters, query or fragment, as `urllib.parse.urlparse` splits it.
fn local_file_url_path(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("file") || rest.contains(['?', '#']) {
        return None;
    }
    let path = match rest.strip_prefix("//") {
        Some(authority) => {
            let split = authority.find('/').unwrap_or(authority.len());
            if !matches!(&authority[..split], "" | "localhost") {
                return None;
            }
            &authority[split..]
        }
        None => rest,
    };
    let last = path.rsplit('/').next().unwrap_or_default();
    (!last.contains(';')).then(|| path.to_owned())
}

/// `urllib.request.url2pathname`, which decodes the path once more.
fn url_to_path(path: &str) -> PathBuf {
    let decoded = py_unquote(path);
    if cfg!(windows) {
        let trimmed = decoded.trim_start_matches('/');
        let drive = trimmed.as_bytes();
        let windows = if drive.len() >= 2 && drive[0].is_ascii_alphabetic() && drive[1] == b':' {
            trimmed.to_owned()
        } else {
            decoded.clone()
        };
        return PathBuf::from(windows.replace('/', "\\"));
    }
    PathBuf::from(decoded)
}

/// The neutral directory the probe runs in: the preparation scope the parent
/// created, or `runtime/python-probe` under the Guard home, made here.
pub(super) fn probe_dir(
    value: Option<&Value>,
) -> Result<Result<PathBuf, &'static str>, &'static str> {
    let map = value
        .and_then(Value::as_object)
        .filter(|map| map.len() == 1)
        .ok_or(ERR_INVALID)?;
    if let Some(scoped) = map.get("scoped") {
        let path = absolute(Some(scoped))?;
        let usable = !path.is_symlink() && owned_private(path);
        return Ok(if usable {
            Ok(path.to_path_buf())
        } else {
            Err(NEUTRAL_CWD_UNAVAILABLE)
        });
    }
    let guard_home = absolute(map.get("guard_home"))?;
    Ok(guard_probe_dir(guard_home).ok_or(NEUTRAL_CWD_UNAVAILABLE))
}

fn guard_probe_dir(guard_home: &Path) -> Option<PathBuf> {
    create_private(guard_home, true)?;
    let home = resolve(guard_home).ok()?;
    if !owned(&home) || mode(&home).is_some_and(|mode| mode & 0o022 != 0) {
        return None;
    }
    let runtime = home.join("runtime");
    let probe = runtime.join("python-probe");
    for directory in [&runtime, &probe] {
        create_private(directory, false)?;
        if directory.is_symlink() || !owned(directory) {
            return None;
        }
        restrict(directory)?;
        if !owned_private(directory) {
            return None;
        }
    }
    resolve(&probe).ok()
}

/// `Path.mkdir(mode=0o700, exist_ok=True)`, with parents when asked.
fn create_private(path: &Path, parents: bool) -> Option<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(parents);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Some(()),
        Err(_) if path.is_dir() => Some(()),
        Err(_) => None,
    }
}

fn restrict(path: &Path) -> Option<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).ok()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Some(())
    }
}

/// The permission bits, where the platform has them.
fn mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path)
            .ok()
            .map(|metadata| metadata.mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// A directory this user owns.
fn owned(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_dir() && metadata.uid() == nix::unistd::getuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        metadata.is_dir()
    }
}

fn owned_private(path: &Path) -> bool {
    owned(path) && mode(path).is_none_or(|mode| mode & 0o077 == 0)
}

#[cfg(test)]
#[path = "hook_python_expect_tests.rs"]
mod tests;
