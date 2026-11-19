//! The environment and command contracts of a hook child: the variable
//! allowlist, the signed Desktop proxy selectors, the isolated Guard CLI and
//! daemon-start commands, and the private runtime directory a hook runs in.
//! Split from `hook_process_spawn` as a `#[path]` child module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `_HOOK_ENVIRONMENT_KEYS` (`codex_hook_launch_runtime.py:30-52`): the only
/// base-env keys forwarded to a contained hook process. `LC_*` is a prefix
/// allowlist on top.
pub(super) const HOOK_ENVIRONMENT_KEYS: [&str; 20] = [
    "CODEX_HOME",
    "COMSPEC",
    "HOME",
    "HOL_GUARD_HOOK_FAILURE_KIND",
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_NATIVE_BINARY",
    // A source checkout names its source compiler; the compiler refuses either
    // override when a packaged compiler is present.
    "HOL_GUARD_NATIVE_SOURCE_COMPILER",
    "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER",
    "HOL_GUARD_TEST_MODE",
    "HOL_GUARD_NATIVE_DIAGNOSTIC",
    "HOL_GUARD_RESIDENT_TEST_SEAMS",
    "LANG",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
    "WINDIR",
];

fn env_key_allowed(name: &str) -> bool {
    let upper = name.to_uppercase();
    HOOK_ENVIRONMENT_KEYS.iter().any(|k| upper == *k) || upper.starts_with("LC_")
}

/// `desktop_hook_proxy_context`: only the signed Desktop proxy selectors cross
/// a hook boundary, and only when the proxy is an absolute path.
pub(crate) fn desktop_hook_proxy_context(
    source: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut selected = BTreeMap::new();
    if source.get("HOL_GUARD_DESKTOP").map(String::as_str) != Some("1") {
        return selected;
    }
    let Some(proxy) = source.get("HOL_GUARD_DESKTOP_HOOK_PROXY") else {
        return selected;
    };
    if proxy.is_empty() || proxy.contains('\0') || !Path::new(proxy).is_absolute() {
        return selected;
    }
    selected.insert("HOL_GUARD_DESKTOP".to_owned(), "1".to_owned());
    selected.insert("HOL_GUARD_DESKTOP_HOOK_PROXY".to_owned(), proxy.clone());
    selected
}

/// `isolated_hook_environment`: OS, user-home, locale, temp, PATH, Codex,
/// native and signed proxy state, and nothing else.
pub fn isolated_hook_environment(source: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut kept: BTreeMap<String, String> = source
        .iter()
        .filter(|(k, _)| env_key_allowed(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    kept.extend(desktop_hook_proxy_context(source));
    kept
}

/// `isolated_guard_cli_command` (`codex_hook_launch_runtime.py:171-184`):
/// the exact isolated fallback contract pinned to one package root.
pub fn isolated_guard_cli_command(
    python_executable: &str,
    package_root: &Path,
    guard_args: &[String],
) -> Vec<String> {
    let bootstrap = format!(
        "import sys;sys.path.insert(0, {});from codex_plugin_scanner.cli import main;raise SystemExit(main(sys.argv[1:]))",
        py_repr(&canonical_or_self(package_root)),
    );
    let mut cmd = vec![
        python_executable.to_string(),
        "-I".to_string(),
        "-c".to_string(),
        bootstrap,
    ];
    cmd.extend(guard_args.iter().cloned());
    cmd
}

/// `isolated_daemon_start_command` (`codex_hook_launch_runtime.py`).
/// `home_dir` is the authenticated canonical home; `None` = `Path.home()`.
pub fn isolated_daemon_start_command(
    python_executable: &str,
    package_root: &Path,
    guard_home: &Path,
    home_dir: Option<&Path>,
) -> Vec<String> {
    let resolved_home = home_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(home_fallback);
    let bootstrap = format!(
        "import os,sys;sys.path.insert(0, {});from pathlib import Path;\
from codex_plugin_scanner.guard.native_daemon_manage import schedule_guard_daemon_recovery;\
failure_kind=os.environ.get('HOL_GUARD_HOOK_FAILURE_KIND','transport-failure');\
failure_kind=failure_kind if failure_kind in \
{{'overload','transport-failure','authenticated-control-plane-failure'}} \
else 'transport-failure';\
schedule_guard_daemon_recovery(Path({}),home_dir=Path({}),failure_kind=failure_kind)",
        py_repr(&canonical_or_self(package_root)),
        py_repr(guard_home),
        py_repr(&resolved_home),
    );
    vec![
        python_executable.to_string(),
        "-I".to_string(),
        "-c".to_string(),
        bootstrap,
    ]
}

#[allow(dead_code)]
fn home_fallback() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// `Path.resolve()`, spelled as Python spells it on every platform.
fn canonical_or_self(p: &Path) -> PathBuf {
    crate::codex_hook_bridge_trust_files::canonical(p)
}

/// Python `repr()` of a path string — `Path('…')` needs a quoted literal.
fn py_repr(p: &Path) -> String {
    crate::guard_store_json::py_repr_str(&p.as_os_str().to_string_lossy())
}

/// `private_hook_runtime_cwd` (`codex_hook_launch_runtime.py:227-247`):
/// return the authenticated manifest's private Guard-owned directory.
/// Errors map to `Err("…")` mirroring the Python `ValueError` messages.
#[allow(dead_code)]
pub fn private_hook_runtime_cwd(manifest_path: &Path) -> Result<PathBuf, String> {
    let parent = manifest_path
        .parent()
        .ok_or_else(|| "managed Codex hook runtime directory is unavailable".to_string())?;
    let parent_meta = std::fs::symlink_metadata(parent)
        .map_err(|_| "managed Codex hook runtime directory is unavailable".to_string())?;
    let resolved = std::fs::canonicalize(parent)
        .map_err(|_| "managed Codex hook runtime directory is unavailable".to_string())?;
    let _resolved_meta = std::fs::symlink_metadata(&resolved)
        .map_err(|_| "managed Codex hook runtime directory is unavailable".to_string())?;

    if parent_meta.file_type().is_symlink() || !parent_meta.file_type().is_dir() {
        return Err("managed Codex hook runtime directory is not a regular directory".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (parent_meta.dev(), parent_meta.ino()) != (_resolved_meta.dev(), _resolved_meta.ino()) {
            return Err(
                "managed Codex hook runtime directory changed during validation".to_string(),
            );
        }
        let current_uid = nix::unistd::getuid().as_raw();
        if parent_meta.uid() != current_uid {
            return Err("managed Codex hook runtime directory has an unexpected owner".to_string());
        }
        if parent_meta.mode() & 0o077 != 0 {
            return Err("managed Codex hook runtime directory is not owner-only".to_string());
        }
    }
    Ok(resolved)
}
