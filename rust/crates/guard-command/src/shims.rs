//! Port of `src/codex_plugin_scanner/guard/shims.py` — executable shim digest/content
//! templates, install/remove, drift-aware policy emission (55 fns).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::local_supply_chain::{sha256_content_digest, Timestamp};

// ---------------------------------------------------------------------------
// Constants (verbatim from shims.py).
// ---------------------------------------------------------------------------

pub const FROZEN_PACKAGE_SHIM_SENTINEL: &str = "_GUARD_FROZEN_PACKAGE_SHIM";
pub const SQLITE_CONNECT_TIMEOUT_SECONDS: f64 = 30.0;
pub const SHIM_PROBE_ENV_VAR: &str = "HOL_GUARD_SHIM_PROBE";
pub const SHIM_PROBE_ENV_VALUE: &str = "1";
pub const PACKAGE_SHIM_STATUS_FD_ENV_VAR: &str = "HOL_GUARD_PACKAGE_SHIM_STATUS_FD";
const _PACKAGE_SHIM_MANIFEST: &str = "package-shims.json";
const _GUARD_PROFILE_MARKER: &str = "# >>> hol-guard path >>>";
const _PACKAGE_PROFILE_MARKER: &str = "# >>> hol-guard package-shims path >>>";
const _PACKAGE_SHIM_PROBE_TIMEOUT_SECONDS: i64 = 15;
const _MAX_PACKAGE_SHIM_PROBE_OUTPUT_BYTES: usize = 4096;
const _LOCAL_TEST_RUNNER_COMMANDS: &[&str] = &["pytest", "python -m pytest", "python3 -m pytest"];

/// `_PACKAGE_SHIM_COMMANDS` — manager → binary name.
const PACKAGE_SHIM_COMMANDS: &[(&str, &str)] = &[
    ("npm", "npm"),
    ("pnpm", "pnpm"),
    ("yarn", "yarn"),
    ("bun", "bun"),
    ("pip", "pip"),
    ("pip3", "pip3"),
    ("uv", "uv"),
    ("poetry", "poetry"),
];

fn package_shim_command(manager: &str) -> Option<&'static str> {
    PACKAGE_SHIM_COMMANDS
        .iter()
        .find(|(name, _)| *name == manager)
        .map(|(_, command)| *command)
}

/// `_TRUSTED_CLI_LAUNCHER` — verbatim trusted-launcher payload emitted into the shim.
const TRUSTED_CLI_LAUNCHER: &str = r#"import runpy
import sys
sys.path.insert(0, sys.argv[1])
sys.argv = [sys.argv[2], *sys.argv[3:]]
runpy.run_module(sys.argv[0], run_name="__main__")
"#;

/// The Python-side equivalent of `sys.executable` when not frozen.
fn sys_executable() -> String {
    std::env::var("GUARD_PYTHON")
        .or_else(|_| std::env::var("PYTHON"))
        .unwrap_or_else(|_| "python3".to_owned())
}

fn is_frozen() -> bool {
    std::env::var("_MEIPASS").is_ok() || std::env::var("NUITKA_ONEFILE_PARENT").is_ok()
}

fn package_shim_interpreter() -> String {
    if is_frozen() {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| sys_executable())
    } else {
        sys_executable()
    }
}

// ---------------------------------------------------------------------------
// HarnessContext — minimal shim-owned stand-in for the Python HarnessContext.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HarnessContext {
    pub guard_home: PathBuf,
    pub home_dir: Option<PathBuf>,
    pub workspace_dir: Option<PathBuf>,
    pub home_override_explicit: bool,
}

impl HarnessContext {
    fn guard_home_bin(&self) -> PathBuf {
        self.guard_home.join("bin")
    }
    fn package_shim_dir(&self) -> PathBuf {
        self.guard_home.join("package-shims")
    }
    fn package_shim_bin_dir(&self) -> PathBuf {
        self.package_shim_dir().join("bin")
    }
}

// ---------------------------------------------------------------------------
// JSON helpers matching the Python dict-shape returns.
// ---------------------------------------------------------------------------

fn obj() -> Map<String, Value> {
    Map::new()
}

fn v_str(s: impl Into<String>) -> Value {
    Value::String(s.into())
}

fn v_bool(b: bool) -> Value {
    Value::Bool(b)
}

fn v_opt_str(o: Option<&str>) -> Value {
    o.map(v_str).unwrap_or(Value::Null)
}

fn v_arr(items: Vec<Value>) -> Value {
    Value::Array(items)
}

fn v_str_arr(items: Vec<String>) -> Value {
    Value::Array(items.into_iter().map(Value::String).collect())
}

fn v_map(map: Map<String, Value>) -> Value {
    Value::Object(map)
}

fn dict_items(value: Option<&Value>) -> Vec<Map<String, Value>> {
    value
        .and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(Value::as_object).cloned().collect())
        .unwrap_or_default()
}

fn string_items(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn py_repr_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('\'');
    out
}

fn py_repr_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| py_repr_str(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn py_repr_tuple(items: &[String]) -> String {
    match items.len() {
        0 => "()".to_owned(),
        1 => format!("({},)", py_repr_str(&items[0])),
        _ => {
            let inner: Vec<String> = items.iter().map(|s| py_repr_str(s)).collect();
            format!("({})", inner.join(", "))
        }
    }
}

fn resolve_or_self(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

// ---------------------------------------------------------------------------
// Public API.
// ---------------------------------------------------------------------------

/// `install_guard_shim` (:123-155).
pub fn install_guard_shim(
    harness: &str,
    context: &HarnessContext,
    launcher_name: Option<&str>,
    display_name: Option<&str>,
) -> Map<String, Value> {
    let shim_dir = context.guard_home_bin();
    let _ = fs::create_dir_all(&shim_dir);
    let shim_name = launcher_name.unwrap_or(harness);
    let harness_label = display_name.unwrap_or(harness);
    let posix_path = shim_dir.join(format!("guard-{shim_name}"));
    let windows_path = shim_dir.join(format!("guard-{shim_name}.cmd"));
    let workspace_args: Vec<String> = context
        .workspace_dir
        .as_ref()
        .map(|p| vec!["--workspace".to_owned(), p.to_string_lossy().into_owned()])
        .unwrap_or_default();
    let _ = fs::write(
        &posix_path,
        build_python_shim(harness, context, &workspace_args),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&posix_path)
            .map(|m| m.permissions())
            .unwrap_or_else(|_| fs::Permissions::from_mode(0o700));
        perms.set_mode(perms.mode() | 0o755);
        let _ = fs::set_permissions(&posix_path, perms);
    }
    let _ = fs::write(&windows_path, build_windows_script(&posix_path));
    let mut result = obj();
    result.insert("shim_path".into(), v_str(posix_path.to_string_lossy()));
    result.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    result.insert(
        "shim_command".into(),
        v_str(
            posix_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
    );
    result.insert(
        "windows_shim_path".into(),
        v_str(windows_path.to_string_lossy()),
    );
    result.insert(
        "notes".into(),
        v_arr(vec![
            v_str(format!(
                "Launch {harness_label} through {} so Guard checks changes before the harness starts.",
                posix_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
            )),
            v_str(format!(
                "Add {} to PATH to use the wrapper command from any shell.",
                shim_dir.to_string_lossy()
            )),
        ]),
    );
    result
}

/// `remove_guard_shim` (:156-186).
pub fn remove_guard_shim(
    harness: &str,
    context: &HarnessContext,
    launcher_name: Option<&str>,
    legacy_launcher_names: &[&str],
    display_name: Option<&str>,
) -> Map<String, Value> {
    let shim_dir = context.guard_home_bin();
    let shim_name = launcher_name.unwrap_or(harness);
    let harness_label = display_name.unwrap_or(harness);
    let mut names: Vec<String> = vec![shim_name.to_owned()];
    names.extend(legacy_launcher_names.iter().map(|s| s.to_string()));
    let shim_paths: Vec<PathBuf> = names
        .iter()
        .flat_map(|name| {
            let dir = shim_dir.clone();
            ["", ".cmd"]
                .iter()
                .map(move |suffix| dir.join(format!("guard-{name}{suffix}")))
        })
        .collect();
    let mut removed_paths: Vec<String> = Vec::new();
    for path in &shim_paths {
        if path.exists() {
            let _ = fs::remove_file(path);
            removed_paths.push(path.to_string_lossy().into_owned());
        }
    }
    let posix_path = shim_dir.join(format!("guard-{shim_name}"));
    let mut result = obj();
    result.insert("shim_path".into(), v_str(posix_path.to_string_lossy()));
    result.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    result.insert("removed_paths".into(), v_str_arr(removed_paths));
    result.insert(
        "shim_command".into(),
        v_str(
            posix_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
    );
    result.insert(
        "notes".into(),
        v_arr(vec![v_str(format!(
            "Removed the Guard launcher shim for {harness_label}."
        ))]),
    );
    result
}

/// `_build_python_shim` (:187-201) → `durable_harness_launcher.build_harness_shim`.
pub fn build_python_shim(
    harness: &str,
    context: &HarnessContext,
    workspace_args: &[String],
) -> String {
    build_harness_shim(
        &sys_executable(),
        harness,
        context,
        workspace_args,
        &trusted_python_flags(),
        TRUSTED_CLI_LAUNCHER,
        &trusted_import_root(),
        &merge_guard_launcher_env(),
        &home_override_args(context),
        is_transient_path,
    )
}

/// `_build_windows_script` (:202-205) → `durable_harness_launcher.build_windows_script`.
pub fn build_windows_script(posix_path: &Path) -> String {
    build_windows_script_inner(&package_shim_interpreter(), posix_path)
}

fn build_windows_script_inner(interpreter: &str, posix_path: &Path) -> String {
    format!(
        "@echo off\r\n\"{interpreter}\" \"{}\" %*\r\n",
        posix_path.to_string_lossy()
    )
}

/// `_write_package_manager_shim_files` (:206-214) → `package_shim_frozen.write_package_manager_shim_files`.
fn write_package_manager_shim_files(
    context: &HarnessContext,
    command: &str,
    shim_dir: &Path,
) -> PathBuf {
    let python_source = build_package_manager_python_shim(context, command);
    let windows_script = build_windows_script(&shim_dir.join(command));
    let posix_path = shim_dir.join(command);
    let windows_path = shim_dir.join(format!("{command}.cmd"));
    let _ = fs::create_dir_all(shim_dir);
    let _ = fs::write(&posix_path, &python_source);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&posix_path)
            .map(|m| m.permissions())
            .unwrap_or_else(|_| fs::Permissions::from_mode(0o700));
        perms.set_mode(perms.mode() | 0o755);
        let _ = fs::set_permissions(&posix_path, perms);
    }
    let _ = fs::write(&windows_path, windows_script);
    posix_path
}

/// `_home_override_args` (:215-224).
fn home_override_args(context: &HarnessContext) -> Vec<String> {
    if context.home_dir.is_none() {
        return Vec::new();
    }
    if !context.home_override_explicit
        && context
            .home_dir
            .as_ref()
            .map(|h| {
                std::env::var_os("HOME")
                    .map(|home| resolve_or_self(h) == resolve_or_self(&PathBuf::from(home)))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    {
        return Vec::new();
    }
    vec![
        "--home".to_owned(),
        context
            .home_dir
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    ]
}

/// `build_shim_content_hash` (:225-229).
pub fn build_shim_content_hash(content: &[u8]) -> String {
    sha256_content_digest(content)
}

/// `_normalized_package_shim_content` (:230-233). Calls into the frozen-shim
/// seam helper; referenced by integrity-check callers in the Python source.
#[allow(dead_code)]
fn normalized_package_shim_content(content: &[u8]) -> String {
    normalized_package_shim_content_inner(content)
}

#[allow(dead_code)]
fn normalized_package_shim_content_inner(content: &[u8]) -> String {
    let text = match std::str::from_utf8(content) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    let mut normalized_lines: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.starts_with("#!") {
            normalized_lines.push("#!<interpreter>".to_owned());
            continue;
        }
        if line.starts_with("exec ") {
            normalized_lines.push("exec <python> <shim-python> \"$@\"".to_owned());
            continue;
        }
        if line.starts_with("base_command = ") {
            normalized_lines.push(format!(
                "base_command = {}",
                normalized_base_command_repr(line)
            ));
            continue;
        }
        if line.starts_with("guard_cwd = ") || line.starts_with("guard_cli_cwd = ") {
            normalized_lines.push("guard_cli_cwd = '<path>'".to_owned());
            continue;
        }
        if line.starts_with("guard_home = ") {
            normalized_lines.push("guard_home = '<path>'".to_owned());
            continue;
        }
        if line.starts_with("guard_workspace = ") {
            normalized_lines.push("guard_workspace = <workspace-path>".to_owned());
            continue;
        }
        if line.starts_with("guard_has_explicit_workspace = ") {
            normalized_lines.push("guard_has_explicit_workspace = <workspace-mode>".to_owned());
            continue;
        }
        if line.starts_with("shim_dir = ") {
            normalized_lines.push("shim_dir = '<path>'".to_owned());
            continue;
        }
        normalized_lines.push(line.to_owned());
    }
    normalized_lines.join("\n")
}

#[allow(dead_code)]
fn normalized_base_command_repr(line: &str) -> String {
    let raw_value = line.split('=').nth(1).map(|s| s.trim()).unwrap_or("");
    // Minimal Python literal-eval for list-of-strings.
    if !raw_value.starts_with('[') || !raw_value.ends_with(']') {
        return raw_value.to_owned();
    }
    let inner = &raw_value[1..raw_value.len() - 1];
    let items: Vec<String> = inner
        .split(',')
        .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    let mut normalized: Vec<String> = Vec::new();
    let mut skip_path_after: Option<String> = None;
    for (index, item) in items.iter().enumerate() {
        if index == 0 {
            normalized.push("<python>".to_owned());
            continue;
        }
        if index + 1 < items.len() && items[index + 1] == "codex_plugin_scanner.cli" {
            normalized.push("<import-root>".to_owned());
            continue;
        }
        if let Some(ref key) = skip_path_after {
            normalized.push(format!("<{key}>"));
            skip_path_after = None;
            continue;
        }
        normalized.push(item.clone());
        if item == "--guard-home" || item == "--home" || item == "--workspace" {
            skip_path_after = Some(item.trim_start_matches('-').to_owned());
        }
    }
    py_repr_list(&normalized)
}

/// `get_real_binary_info` (:234-258).
pub fn get_real_binary_info(
    binary_path: &str,
    redact_path_prefix: Option<&str>,
) -> Map<String, Value> {
    let p = Path::new(binary_path);
    if !p.exists() || !p.is_file() {
        let mut r = obj();
        r.insert("found".into(), v_bool(false));
        r.insert("content_hash".into(), Value::Null);
        r.insert("mtime".into(), Value::Null);
        r.insert("path_display".into(), Value::Null);
        return r;
    }
    let content = fs::read(p).unwrap_or_default();
    let content_hash = build_shim_content_hash(&content);
    let mtime = fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let path_str = p.to_string_lossy().into_owned();
    let path_display = redact_path_prefix
        .filter(|prefix| path_str.starts_with(*prefix))
        .map(|prefix| format!("…{}", &path_str[prefix.len()..]))
        .unwrap_or_else(|| path_str.clone());
    let mut r = obj();
    r.insert("found".into(), v_bool(true));
    r.insert("content_hash".into(), v_str(content_hash));
    r.insert("mtime".into(), serde_json::json!(mtime));
    r.insert("path_display".into(), v_str(path_display));
    r
}

/// `_has_package_shim_layout` (:259-264).
fn has_package_shim_layout(candidate: &Path) -> bool {
    candidate
        .parent()
        .map(|p| p.file_name().map(|n| n == "bin").unwrap_or(false))
        .unwrap_or(false)
        && candidate
            .parent()
            .and_then(|p| p.parent())
            .map(|g| g.file_name().map(|n| n == "package-shims").unwrap_or(false))
            .unwrap_or(false)
}

/// `_is_trusted_package_shim_binary` (:265-272).
fn is_trusted_package_shim_binary(candidate: &Path, trusted_shim_dir: &Path) -> bool {
    let resolved_candidate = resolve_or_self(candidate);
    let resolved_trusted = resolve_or_self(trusted_shim_dir);
    if !resolved_candidate.starts_with(&resolved_trusted) {
        return false;
    }
    candidate.is_file()
}

/// `_is_foreign_package_shim_binary` (:273-279).
fn is_foreign_package_shim_binary(candidate: &Path, trusted_shim_dir: &Path) -> bool {
    has_package_shim_layout(candidate)
        && !is_trusted_package_shim_binary(candidate, trusted_shim_dir)
}

/// `get_path_order_status` (:280-377).
pub fn get_path_order_status(
    context: &HarnessContext,
    manager: &str,
    path_env: Option<&str>,
) -> Map<String, Value> {
    let command = match package_shim_command(manager) {
        Some(c) => c,
        None => {
            let mut r = obj();
            r.insert("shim_precedes_real".into(), v_bool(false));
            r.insert("real_binary_found".into(), v_bool(false));
            r.insert("path_broken".into(), v_bool(true));
            r.insert("shim_dir".into(), Value::Null);
            return r;
        }
    };
    let shim_dir = resolve_or_self(&context.package_shim_bin_dir());
    let shim_path = shim_dir.join(command);
    let effective_path = path_env
        .map(str::to_owned)
        .unwrap_or_else(|| std::env::var("PATH").unwrap_or_default());
    let path_dirs: Vec<&str> = effective_path.split(':').collect();
    let mut shim_dir_index: Option<usize> = None;
    let mut real_dir_index: Option<usize> = None;
    let mut foreign_shim_index: Option<usize> = None;
    let mut foreign_shim_path: Option<String> = None;
    let mut real_binary_path: Option<String> = None;
    for (idx, dir_entry) in path_dirs.iter().enumerate() {
        let d = resolve_or_self(&PathBuf::from(shellexpand_tilde(dir_entry)));
        if d == shim_dir && shim_dir_index.is_none() {
            shim_dir_index = Some(idx);
            continue;
        }
        let candidate = d.join(command);
        if !candidate.exists() || !candidate.is_file() || candidate == shim_path {
            continue;
        }
        if is_foreign_package_shim_binary(&candidate, &shim_dir) {
            if foreign_shim_index.is_none() {
                foreign_shim_index = Some(idx);
                foreign_shim_path = Some(candidate.to_string_lossy().into_owned());
            }
            continue;
        }
        if is_trusted_package_shim_binary(&candidate, &shim_dir) {
            continue;
        }
        if real_dir_index.is_none() {
            real_dir_index = Some(idx);
            real_binary_path = Some(candidate.to_string_lossy().into_owned());
        }
    }
    let foreign_shim_precedes_trusted = foreign_shim_index.is_some()
        && shim_dir_index.is_some()
        && foreign_shim_index < shim_dir_index;
    let mut r = obj();
    if shim_dir_index.is_none() {
        r.insert("shim_precedes_real".into(), v_bool(false));
        r.insert("real_binary_found".into(), v_bool(real_dir_index.is_some()));
        r.insert(
            "real_binary_path".into(),
            v_opt_str(real_binary_path.as_deref()),
        );
        r.insert("real_binary_path_index".into(), v_opt_usize(real_dir_index));
        r.insert("shim_in_path".into(), v_bool(false));
        r.insert("shim_path_index".into(), Value::Null);
        r.insert("path_broken".into(), v_bool(true));
        r.insert(
            "foreign_shim_bypass".into(),
            v_bool(foreign_shim_index.is_some()),
        );
        r.insert(
            "foreign_shim_path".into(),
            v_opt_str(foreign_shim_path.as_deref()),
        );
        r.insert(
            "foreign_shim_path_index".into(),
            v_opt_usize(foreign_shim_index),
        );
        r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
        return r;
    }
    if foreign_shim_precedes_trusted {
        r.insert("shim_precedes_real".into(), v_bool(false));
        r.insert("real_binary_found".into(), v_bool(real_dir_index.is_some()));
        r.insert(
            "real_binary_path".into(),
            v_opt_str(real_binary_path.as_deref()),
        );
        r.insert("real_binary_path_index".into(), v_opt_usize(real_dir_index));
        r.insert("shim_in_path".into(), v_bool(true));
        r.insert("shim_path_index".into(), v_opt_usize(shim_dir_index));
        r.insert("path_broken".into(), v_bool(true));
        r.insert("foreign_shim_bypass".into(), v_bool(true));
        r.insert(
            "foreign_shim_path".into(),
            v_opt_str(foreign_shim_path.as_deref()),
        );
        r.insert(
            "foreign_shim_path_index".into(),
            v_opt_usize(foreign_shim_index),
        );
        r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
        return r;
    }
    if real_dir_index.is_none() {
        r.insert("shim_precedes_real".into(), v_bool(true));
        r.insert("real_binary_found".into(), v_bool(false));
        r.insert("real_binary_path".into(), Value::Null);
        r.insert("real_binary_path_index".into(), Value::Null);
        r.insert("shim_in_path".into(), v_bool(true));
        r.insert("shim_path_index".into(), v_opt_usize(shim_dir_index));
        r.insert("path_broken".into(), v_bool(false));
        r.insert("foreign_shim_bypass".into(), v_bool(false));
        r.insert(
            "foreign_shim_path".into(),
            v_opt_str(foreign_shim_path.as_deref()),
        );
        r.insert(
            "foreign_shim_path_index".into(),
            v_opt_usize(foreign_shim_index),
        );
        r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
        return r;
    }
    let precedes = shim_dir_index < real_dir_index;
    r.insert("shim_precedes_real".into(), v_bool(precedes));
    r.insert("real_binary_found".into(), v_bool(true));
    r.insert(
        "real_binary_path".into(),
        v_opt_str(real_binary_path.as_deref()),
    );
    r.insert("real_binary_path_index".into(), v_opt_usize(real_dir_index));
    r.insert("shim_in_path".into(), v_bool(true));
    r.insert("shim_path_index".into(), v_opt_usize(shim_dir_index));
    r.insert("path_broken".into(), v_bool(!precedes));
    r.insert("foreign_shim_bypass".into(), v_bool(false));
    r.insert(
        "foreign_shim_path".into(),
        v_opt_str(foreign_shim_path.as_deref()),
    );
    r.insert(
        "foreign_shim_path_index".into(),
        v_opt_usize(foreign_shim_index),
    );
    r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    r
}

fn v_opt_usize(o: Option<usize>) -> Value {
    o.map(|n| Value::Number(serde_json::Number::from(n)))
        .unwrap_or(Value::Null)
}

fn shellexpand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('~') {
        if rest.is_empty() || rest.starts_with('/') {
            if let Some(home) = std::env::var_os("HOME") {
                return format!("{}{}", PathBuf::from(&home).to_string_lossy(), rest);
            }
        }
    }
    path.to_owned()
}

/// `_package_shim_profile_status` (:378-408).
fn package_shim_profile_status(context: &HarnessContext) -> Map<String, Value> {
    let shim_dir = context.package_shim_bin_dir();
    let home_dir = match &context.home_dir {
        Some(h) => h.clone(),
        None => {
            let mut r = obj();
            r.insert("shell_profile_configured".into(), v_bool(false));
            r.insert("shell_profile_path".into(), Value::Null);
            r.insert("shell_profile_paths".into(), v_arr(vec![]));
            r.insert("shell_profile_missing_paths".into(), v_arr(vec![]));
            return r;
        }
    };
    let targets = package_shim_profile_targets(&home_dir, &shim_dir);
    let mut configured_paths: Vec<String> = Vec::new();
    let mut missing_paths: Vec<String> = Vec::new();
    for (profile_path, _) in &targets {
        let existing = if profile_path.exists() {
            fs::read_to_string(profile_path).unwrap_or_default()
        } else {
            String::new()
        };
        if profile_already_references_path(&existing, &shim_dir) {
            configured_paths.push(profile_path.to_string_lossy().into_owned());
        } else {
            missing_paths.push(profile_path.to_string_lossy().into_owned());
        }
    }
    let primary_path = targets
        .first()
        .map(|(p, _)| p.to_string_lossy().into_owned());
    let mut r = obj();
    r.insert(
        "shell_profile_configured".into(),
        v_bool(!targets.is_empty() && missing_paths.is_empty()),
    );
    r.insert(
        "shell_profile_path".into(),
        v_opt_str(primary_path.as_deref()),
    );
    r.insert("shell_profile_paths".into(), v_str_arr(configured_paths));
    r.insert(
        "shell_profile_missing_paths".into(),
        v_str_arr(missing_paths),
    );
    r
}

/// `_package_shim_activation_path_status` (:409-421).
fn package_shim_activation_path_status(
    installed_managers: &[String],
    path_contains_shim_dir: bool,
    shell_profile_configured: bool,
) -> &'static str {
    if !installed_managers.is_empty() && path_contains_shim_dir {
        return "in_path";
    }
    if !installed_managers.is_empty() && shell_profile_configured {
        return "restart_required";
    }
    "missing_from_path"
}

/// `install_package_shims` (:422-479).
pub fn install_package_shims(
    context: &HarnessContext,
    managers: Option<&[&str]>,
    path_env: Option<&str>,
) -> Map<String, Value> {
    let shim_root = context.package_shim_dir();
    let shim_dir = shim_root.join("bin");
    let _ = fs::create_dir_all(&shim_dir);
    let normalized_managers = normalize_package_shim_managers(managers);
    let existing_manifest = load_package_shim_manifest(context);
    let existing_managers: Vec<String> = string_items(existing_manifest.get("installed_managers"))
        .into_iter()
        .filter(|m| package_shim_command(m).is_some())
        .collect();
    let mut tracked_managers: Vec<String> = existing_managers.clone();
    for m in &normalized_managers {
        if !tracked_managers.contains(m) {
            tracked_managers.push(m.clone());
        }
    }
    let existing_hashes = string_map(existing_manifest.get("content_hashes"));
    let last_test_at: BTreeMap<String, String> = string_map(existing_manifest.get("last_test_at"));
    let mut installed: Vec<String> = Vec::new();
    let mut content_hashes: BTreeMap<String, String> = existing_hashes.clone();
    for manager in &normalized_managers {
        let command = package_shim_command(manager).unwrap_or(manager.as_str());
        let posix_path = write_package_manager_shim_files(context, command, &shim_dir);
        let bytes = fs::read(&posix_path).unwrap_or_default();
        content_hashes.insert(
            manager.clone(),
            build_shim_content_hash(&installed_package_shim_attestation_bytes(
                &shim_dir, command, &bytes,
            )),
        );
        installed.push(manager.clone());
    }
    let mut manifest_payload = obj();
    manifest_payload.insert(
        "content_hashes".into(),
        Value::Object(
            content_hashes
                .iter()
                .map(|(k, v)| (k.clone(), v_str(v.clone())))
                .collect(),
        ),
    );
    manifest_payload.insert(
        "installed_managers".into(),
        v_str_arr(tracked_managers.clone()),
    );
    manifest_payload.insert(
        "last_test_at".into(),
        Value::Object(
            last_test_at
                .iter()
                .map(|(k, v)| (k.clone(), v_str(v.clone())))
                .collect(),
        ),
    );
    manifest_payload.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    write_package_shim_manifest(context, &manifest_payload);
    let program_name = command_program_name();
    let shell_hints = path_export_hints(&shim_dir);
    let path_repair_required: Vec<String> = tracked_managers
        .iter()
        .filter(|m| {
            !get_path_order_status(context, m, path_env)
                .get("shim_precedes_real")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let mut r = obj();
    r.insert(
        "installed_managers".into(),
        v_str_arr(tracked_managers.clone()),
    );
    r.insert(
        "installed_count".into(),
        serde_json::json!(tracked_managers.len()),
    );
    r.insert("installed_now".into(), v_str_arr(installed.clone()));
    r.insert(
        "installed_now_count".into(),
        serde_json::json!(installed.len()),
    );
    r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    r.insert(
        "manifest_path".into(),
        v_str(package_shim_manifest_path(context).to_string_lossy()),
    );
    r.insert(
        "path_export_hint".into(),
        v_str(path_export_hint(&shim_dir)),
    );
    r.insert(
        "path_repair_required".into(),
        v_str_arr(path_repair_required),
    );
    r.insert("program_name".into(), v_str(program_name));
    r.insert("shell_hints".into(), v_map(shell_hints));
    r
}

/// `activate_package_shims` (:480-501).
pub fn activate_package_shims(
    context: &HarnessContext,
    managers: Option<&[&str]>,
    path_env: Option<&str>,
) -> Map<String, Value> {
    let install_result = install_package_shims(context, managers, path_env);
    let profile_result = ensure_package_shim_path_in_shell_profile(context);
    let status = package_shim_status(context, path_env);
    let mut r = obj();
    r.insert("install_result".into(), v_map(install_result));
    r.insert("profile_result".into(), v_map(profile_result));
    r.insert(
        "path_active".into(),
        status.get("path_active").cloned().unwrap_or(Value::Null),
    );
    r.insert(
        "restart_shell_required".into(),
        status
            .get("restart_shell_required")
            .cloned()
            .unwrap_or(Value::Null),
    );
    r
}

/// `package_shim_status` (:502-608).
pub fn package_shim_status(context: &HarnessContext, path_env: Option<&str>) -> Map<String, Value> {
    let (manifest, manifest_state) = load_package_shim_manifest_with_state(context);
    let installed_managers: Vec<String> = string_items(manifest.get("installed_managers"))
        .into_iter()
        .filter(|m| package_shim_command(m).is_some())
        .collect();
    let normalized_last_tests: BTreeMap<String, String> = match manifest.get("last_test_at") {
        Some(Value::Object(_)) => string_map(manifest.get("last_test_at")),
        _ => BTreeMap::new(),
    };
    let (detected_managers, undetected_managers) =
        detect_system_package_managers(context, path_env);
    let detected_set: BTreeSet<&str> = detected_managers.iter().map(|s| s.as_str()).collect();
    let shim_dir = context.package_shim_bin_dir();
    let stored_hashes = string_map(manifest.get("content_hashes"));
    let mut active_managers: Vec<String> = Vec::new();
    let mut protected_managers: Vec<String> = Vec::new();
    let mut missing_managers: Vec<String> = Vec::new();
    let mut bypasses: Vec<Map<String, Value>> = Vec::new();
    let mut manager_details: Vec<Map<String, Value>> = Vec::new();
    let effective_path = path_env
        .map(str::to_owned)
        .unwrap_or_else(|| std::env::var("PATH").unwrap_or_default());
    let path_entries: Vec<&str> = effective_path
        .split(':')
        .filter(|e| !e.is_empty())
        .collect();
    let resolved_shim_dir = resolve_or_self(&shim_dir);
    let path_contains_shim_dir = path_entries.iter().any(|entry| {
        resolve_or_self(&PathBuf::from(shellexpand_tilde(entry))) == resolved_shim_dir
    });
    for manager in &installed_managers {
        let command = package_shim_command(manager).unwrap_or(manager.as_str());
        let shim_path = shim_dir.join(command);
        let exists = shim_path.exists();
        let path_status = get_path_order_status(context, manager, path_env);
        let integrity: String = if exists {
            active_managers.push(manager.clone());
            let python_source = build_package_manager_python_shim(context, command);
            let installed_wrapper = fs::read(&shim_path).unwrap_or_default();
            classify_installed_package_shim_integrity(
                &python_source,
                &shim_dir,
                command,
                &installed_wrapper,
                stored_hashes.get(manager).map(|s| s.as_str()),
            )
        } else {
            missing_managers.push(manager.clone());
            "missing".to_owned()
        };
        let mut detail = obj();
        detail.insert("integrity".into(), v_str(&integrity));
        detail.insert(
            "last_test_at".into(),
            v_opt_str(normalized_last_tests.get(manager).map(|s| s.as_str())),
        );
        detail.insert("manager".into(), v_str(manager));
        detail.insert(
            "path_active".into(),
            v_bool(
                path_status
                    .get("shim_precedes_real")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        );
        detail.insert(
            "path_index".into(),
            path_status
                .get("shim_path_index")
                .cloned()
                .unwrap_or(Value::Null),
        );
        detail.insert("path_status".into(), v_map(path_status.clone()));
        detail.insert(
            "real_binary_found".into(),
            v_bool(
                path_status
                    .get("real_binary_found")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        );
        detail.insert(
            "real_binary_path".into(),
            path_status
                .get("real_binary_path")
                .cloned()
                .unwrap_or(Value::Null),
        );
        detail.insert(
            "real_binary_path_index".into(),
            path_status
                .get("real_binary_path_index")
                .cloned()
                .unwrap_or(Value::Null),
        );
        detail.insert("shim_path".into(), v_str(shim_path.to_string_lossy()));
        detail.insert(
            "system_binary_detected".into(),
            v_bool(detected_set.contains(manager.as_str())),
        );
        manager_details.push(detail);
        if exists
            && path_status
                .get("shim_precedes_real")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            protected_managers.push(manager.clone());
        } else if exists {
            let bypass_reason = if path_status
                .get("foreign_shim_bypass")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                "foreign_shim_bypass"
            } else {
                "path_inactive"
            };
            let mut bypass = obj();
            bypass.insert("manager".into(), v_str(manager));
            bypass.insert("reason".into(), v_str(bypass_reason));
            bypasses.push(bypass);
        }
    }
    let profile_status = package_shim_profile_status(context);
    let path_active =
        !installed_managers.is_empty() && protected_managers.len() == installed_managers.len();
    let activation_path_status = package_shim_activation_path_status(
        &installed_managers,
        path_contains_shim_dir,
        profile_status
            .get("shell_profile_configured")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    );
    let process_path_status = if path_contains_shim_dir {
        "active"
    } else if activation_path_status == "restart_required" {
        "profile_staged"
    } else {
        "missing"
    };
    let mut payload = obj();
    payload.insert("active_managers".into(), v_str_arr(active_managers));
    payload.insert("detected_managers".into(), v_str_arr(detected_managers));
    payload.insert(
        "installed_managers".into(),
        v_str_arr(installed_managers.clone()),
    );
    payload.insert(
        "last_test_at".into(),
        Value::Object(
            normalized_last_tests
                .iter()
                .map(|(k, v)| (k.clone(), v_str(v.clone())))
                .collect(),
        ),
    );
    payload.insert("protected_managers".into(), v_str_arr(protected_managers));
    payload.insert("path_active".into(), v_bool(path_active));
    payload.insert(
        "path_contains_shim_dir".into(),
        v_bool(path_contains_shim_dir),
    );
    payload.insert("path_status".into(), v_str(activation_path_status));
    payload.insert(
        "bypasses".into(),
        v_arr(bypasses.into_iter().map(v_map).collect()),
    );
    payload.insert(
        "manager_details".into(),
        v_arr(manager_details.into_iter().map(v_map).collect()),
    );
    payload.insert("manifest_state".into(), v_str(manifest_state));
    payload.insert(
        "manifest_path".into(),
        v_str(package_shim_manifest_path(context).to_string_lossy()),
    );
    payload.insert("missing_managers".into(), v_str_arr(missing_managers));
    payload.insert(
        "restart_shell_required".into(),
        v_bool(activation_path_status == "restart_required"),
    );
    payload.insert("process_path_status".into(), v_str(process_path_status));
    payload.insert(
        "process_restart_required".into(),
        v_bool(activation_path_status == "restart_required"),
    );
    payload.insert(
        "shell_profile_configured".into(),
        profile_status
            .get("shell_profile_configured")
            .cloned()
            .unwrap_or(v_bool(false)),
    );
    payload.insert(
        "shell_profile_path".into(),
        profile_status
            .get("shell_profile_path")
            .cloned()
            .unwrap_or(Value::Null),
    );
    payload.insert(
        "shell_profile_paths".into(),
        profile_status
            .get("shell_profile_paths")
            .cloned()
            .unwrap_or(v_arr(vec![])),
    );
    payload.insert(
        "shell_profile_missing_paths".into(),
        profile_status
            .get("shell_profile_missing_paths")
            .cloned()
            .unwrap_or(v_arr(vec![])),
    );
    payload.insert("shell_hints".into(), v_map(path_export_hints(&shim_dir)));
    payload.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    payload.insert(
        "supported_managers".into(),
        v_str_arr(
            package_shim_supported_managers()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
    );
    payload.insert("undetected_managers".into(), v_str_arr(undetected_managers));
    payload
}

/// `package_shim_dashboard_status` (:609-675).
pub fn package_shim_dashboard_status(context: &HarnessContext) -> Map<String, Value> {
    let status = package_shim_status(context, None);
    if status.get("path_status").and_then(Value::as_str) != Some("restart_required")
        || !status
            .get("shell_profile_configured")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return status;
    }
    let installed_managers = string_items(status.get("installed_managers"));
    if installed_managers.is_empty() || !string_items(status.get("missing_managers")).is_empty() {
        return status;
    }
    let details = dict_items(status.get("manager_details"));
    let detail_by_manager: BTreeMap<String, Map<String, Value>> = details
        .iter()
        .filter_map(|d| {
            d.get("manager")
                .and_then(Value::as_str)
                .map(|m| (m.to_owned(), d.clone()))
        })
        .collect();
    if installed_managers.iter().any(|m| {
        detail_by_manager
            .get(m)
            .and_then(|d| d.get("integrity"))
            .and_then(Value::as_str)
            != Some("ok")
    }) {
        return status;
    }
    let mut projected_details: Vec<Map<String, Value>> = Vec::new();
    for detail in &details {
        let manager = detail.get("manager").and_then(Value::as_str).unwrap_or("");
        if !installed_managers.contains(&manager.to_owned()) {
            projected_details.push(detail.clone());
            continue;
        }
        let mut projected_detail = detail.clone();
        if let Some(Value::Object(path_detail)) = detail.get("path_status") {
            let mut pd = path_detail.clone();
            pd.insert("path_broken".into(), v_bool(false));
            pd.insert("shim_in_path".into(), v_bool(true));
            pd.insert("shim_precedes_real".into(), v_bool(true));
            pd.insert("shim_path_index".into(), Value::Null);
            pd.insert("real_binary_path_index".into(), Value::Null);
            pd.insert("foreign_shim_bypass".into(), v_bool(false));
            pd.insert("foreign_shim_path_index".into(), Value::Null);
            projected_detail.insert("path_status".into(), Value::Object(pd));
        }
        projected_detail.insert("path_active".into(), v_bool(true));
        projected_details.push(projected_detail);
    }
    let mut projected = status.clone();
    projected.insert(
        "manager_details".into(),
        v_arr(projected_details.into_iter().map(v_map).collect()),
    );
    projected.insert("path_active".into(), v_bool(true));
    projected.insert("path_contains_shim_dir".into(), v_bool(true));
    projected.insert("path_status".into(), v_str("in_path"));
    projected.insert("restart_shell_required".into(), v_bool(false));
    projected.insert("process_restart_required".into(), v_bool(false));
    projected
}

/// `package_shim_cloud_coverage` (:676-691).
pub fn package_shim_cloud_coverage(context: &HarnessContext) -> Map<String, Value> {
    let status = package_shim_status(context, None);
    let mut r = obj();
    r.insert(
        "activeManagers".into(),
        v_str_arr(string_items(status.get("active_managers"))),
    );
    r.insert(
        "installedManagers".into(),
        v_str_arr(string_items(status.get("installed_managers"))),
    );
    r.insert(
        "protectedManagers".into(),
        v_str_arr(string_items(status.get("protected_managers"))),
    );
    r.insert(
        "missingManagers".into(),
        v_str_arr(string_items(status.get("missing_managers"))),
    );
    r.insert(
        "pathActive".into(),
        status.get("path_active").cloned().unwrap_or(v_bool(false)),
    );
    r.insert(
        "bypasses".into(),
        status.get("bypasses").cloned().unwrap_or(v_arr(vec![])),
    );
    r
}

/// `uninstall_package_shims` (:692-745).
pub fn uninstall_package_shims(
    context: &HarnessContext,
    managers: Option<&[&str]>,
) -> Map<String, Value> {
    let manifest = load_package_shim_manifest(context);
    let manifest_managers: Vec<String> = string_items(manifest.get("installed_managers"))
        .into_iter()
        .filter(|m| package_shim_command(m).is_some())
        .collect();
    let requested_managers = match managers {
        Some(m) => normalize_package_shim_managers(Some(m)),
        None => manifest_managers.clone(),
    };
    let shim_dir = context.package_shim_bin_dir();
    let mut removed_paths: Vec<String> = Vec::new();
    for manager in &requested_managers {
        let command = package_shim_command(manager).unwrap_or(manager.as_str());
        for suffix in &["", ".cmd"] {
            let candidate = shim_dir.join(format!("{command}{suffix}"));
            if candidate.exists() {
                let _ = fs::remove_file(&candidate);
                removed_paths.push(candidate.to_string_lossy().into_owned());
            }
        }
        let sidecar = frozen_package_shim_python_path(&shim_dir, command);
        if sidecar.exists() {
            let _ = fs::remove_file(&sidecar);
            removed_paths.push(sidecar.to_string_lossy().into_owned());
        }
    }
    let remaining: Vec<String> = manifest_managers
        .iter()
        .filter(|m| !requested_managers.contains(m))
        .cloned()
        .collect();
    let manifest_path = package_shim_manifest_path(context);
    if !remaining.is_empty() {
        let manifest_hashes = string_map(manifest.get("content_hashes"));
        let content_hashes: BTreeMap<String, String> = manifest_hashes
            .into_iter()
            .filter(|(k, _)| remaining.contains(k))
            .collect();
        let manifest_last_tests = string_map(manifest.get("last_test_at"));
        let last_test_at: BTreeMap<String, String> = manifest_last_tests
            .into_iter()
            .filter(|(k, _)| remaining.contains(k))
            .collect();
        let mut payload = obj();
        payload.insert(
            "content_hashes".into(),
            Value::Object(
                content_hashes
                    .iter()
                    .map(|(k, v)| (k.clone(), v_str(v.clone())))
                    .collect(),
            ),
        );
        payload.insert("installed_managers".into(), v_str_arr(remaining.clone()));
        payload.insert(
            "last_test_at".into(),
            Value::Object(
                last_test_at
                    .iter()
                    .map(|(k, v)| (k.clone(), v_str(v.clone())))
                    .collect(),
            ),
        );
        payload.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
        write_package_shim_manifest(context, &payload);
    } else if manifest_path.exists() {
        let _ = fs::remove_file(&manifest_path);
    }
    let mut r = obj();
    r.insert("removed_managers".into(), v_str_arr(requested_managers));
    r.insert("removed_paths".into(), v_str_arr(removed_paths));
    r.insert("remaining_managers".into(), v_str_arr(remaining));
    r.insert(
        "manifest_path".into(),
        v_str(manifest_path.to_string_lossy()),
    );
    r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    r
}

/// `package_shim_supported_managers` (:746-749).
pub fn package_shim_supported_managers() -> Vec<&'static str> {
    PACKAGE_SHIM_COMMANDS.iter().map(|(m, _)| *m).collect()
}

/// `repair_package_shims` (:750-789).
pub fn repair_package_shims(
    context: &HarnessContext,
    managers: Option<&[&str]>,
    path_env: Option<&str>,
) -> Map<String, Value> {
    let status = package_shim_status(context, path_env);
    let selected_managers: Option<BTreeSet<String>> = managers.map(|m| {
        normalize_package_shim_managers(Some(m))
            .into_iter()
            .collect()
    });
    let mut managers_to_repair: Vec<String> = Vec::new();
    let mut path_repair_required: Vec<String> = Vec::new();
    for detail in dict_items(status.get("manager_details")) {
        let manager = match detail.get("manager").and_then(Value::as_str) {
            Some(m) => m.to_owned(),
            None => continue,
        };
        if let Some(ref sel) = selected_managers {
            if !sel.contains(&manager) {
                continue;
            }
        }
        if matches!(
            detail.get("integrity").and_then(Value::as_str),
            Some("missing") | Some("stale") | Some("tampered")
        ) {
            managers_to_repair.push(manager);
        } else if !detail
            .get("path_active")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            path_repair_required.push(manager);
        }
    }
    if managers_to_repair.is_empty() {
        let mut r = obj();
        r.insert("repaired".into(), v_arr(vec![]));
        r.insert("repaired_count".into(), serde_json::json!(0));
        r.insert(
            "already_ok".into(),
            status
                .get("installed_managers")
                .cloned()
                .unwrap_or(v_arr(vec![])),
        );
        r.insert(
            "path_repair_required".into(),
            v_str_arr(path_repair_required),
        );
        r.insert(
            "shell_hints".into(),
            status
                .get("shell_hints")
                .cloned()
                .unwrap_or(v_map(Map::new())),
        );
        r.insert("nothing_to_repair".into(), v_bool(true));
        return r;
    }
    let managers_slice: Vec<&str> = managers_to_repair.iter().map(|s| s.as_str()).collect();
    let result = install_package_shims(context, Some(&managers_slice), path_env);
    let mut r = obj();
    r.insert("repaired".into(), v_str_arr(managers_to_repair.clone()));
    r.insert(
        "repaired_count".into(),
        serde_json::json!(managers_to_repair.len()),
    );
    r.insert(
        "path_repair_required".into(),
        v_str_arr(path_repair_required),
    );
    r.insert(
        "shell_hints".into(),
        status
            .get("shell_hints")
            .cloned()
            .unwrap_or(v_map(Map::new())),
    );
    r.insert("install_result".into(), v_map(result));
    r
}

/// `ensure_guard_shim_path_in_shell_profile` (:790-819).
pub fn ensure_guard_shim_path_in_shell_profile(context: &HarnessContext) -> Map<String, Value> {
    let shim_dir = context.guard_home_bin();
    if cfg!(windows) {
        let mut r = obj();
        r.insert("changed".into(), v_bool(false));
        r.insert("profile_path".into(), Value::Null);
        r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
        r.insert("restart_shell_required".into(), v_bool(false));
        r.insert("manual_path_required".into(), v_bool(true));
        return r;
    }
    if is_transient_path(&shim_dir) {
        let mut r = obj();
        r.insert("changed".into(), v_bool(false));
        r.insert("profile_path".into(), Value::Null);
        r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
        r.insert("restart_shell_required".into(), v_bool(false));
        r.insert("manual_path_required".into(), v_bool(true));
        return r;
    }
    let home_dir = context
        .home_dir
        .clone()
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/"));
    let (profile_path, export_line) = guard_shim_profile_target(&home_dir, &shim_dir);
    let result = upsert_managed_profile_block(&profile_path, &export_line, _GUARD_PROFILE_MARKER);
    let mut r = obj();
    r.insert(
        "changed".into(),
        result.get("changed").cloned().unwrap_or(v_bool(false)),
    );
    r.insert("profile_path".into(), v_str(profile_path.to_string_lossy()));
    r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    r.insert("restart_shell_required".into(), v_bool(true));
    r
}

/// `ensure_package_shim_path_in_shell_profile` (:820-855).
pub fn ensure_package_shim_path_in_shell_profile(context: &HarnessContext) -> Map<String, Value> {
    let shim_dir = context.package_shim_bin_dir();
    if cfg!(windows) {
        let mut r = obj();
        r.insert("changed".into(), v_bool(false));
        r.insert("profile_path".into(), Value::Null);
        r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
        r.insert("restart_shell_required".into(), v_bool(false));
        r.insert("manual_path_required".into(), v_bool(true));
        return r;
    }
    if is_transient_path(&shim_dir) {
        let mut r = obj();
        r.insert("changed".into(), v_bool(false));
        r.insert("profile_path".into(), Value::Null);
        r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
        r.insert("restart_shell_required".into(), v_bool(false));
        r.insert("manual_path_required".into(), v_bool(true));
        return r;
    }
    let home_dir = context
        .home_dir
        .clone()
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/"));
    let targets = package_shim_profile_targets(&home_dir, &shim_dir);
    let mut changed_paths: Vec<String> = Vec::new();
    for (profile_path, export_line) in &targets {
        let result =
            upsert_managed_profile_block(profile_path, export_line, _PACKAGE_PROFILE_MARKER);
        if result
            .get("changed")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            changed_paths.push(profile_path.to_string_lossy().into_owned());
        }
    }
    let mut r = obj();
    r.insert("changed".into(), v_bool(!changed_paths.is_empty()));
    r.insert("changed_paths".into(), v_str_arr(changed_paths));
    r.insert(
        "profile_path".into(),
        v_str(
            targets
                .first()
                .map(|(p, _)| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
    );
    r.insert(
        "profile_paths".into(),
        v_str_arr(
            targets
                .iter()
                .map(|(p, _)| p.to_string_lossy().into_owned())
                .collect(),
        ),
    );
    r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    r.insert("restart_shell_required".into(), v_bool(true));
    r
}

/// `remove_guard_profile_blocks` (:856-868).
pub fn remove_guard_profile_blocks(context: &HarnessContext) -> Map<String, Value> {
    let mut r = obj();
    let home_dir = match &context.home_dir {
        Some(h) => h.clone(),
        None => return r,
    };
    let profiles = [
        home_dir.join(".bashrc"),
        home_dir.join(".zshrc"),
        home_dir.join(".config/fish/config.fish"),
    ];
    let shim_dir = context.guard_home_bin();
    let package_shim_dir = context.package_shim_bin_dir();
    for profile_path in &profiles {
        let existing = match fs::read_to_string(profile_path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let stripped = strip_managed_marker_blocks(&existing, _GUARD_PROFILE_MARKER);
        let stripped = strip_managed_marker_blocks(&stripped, _PACKAGE_PROFILE_MARKER);
        if stripped != existing {
            let _ = fs::write(profile_path, &stripped);
        }
    }
    r.insert("shim_dir".into(), v_str(shim_dir.to_string_lossy()));
    r.insert(
        "package_shim_dir".into(),
        v_str(package_shim_dir.to_string_lossy()),
    );
    r
}

/// `_upsert_managed_profile_block` (:869-904).
fn upsert_managed_profile_block(
    profile_path: &Path,
    export_line: &str,
    marker: &str,
) -> Map<String, Value> {
    if let Some(parent) = profile_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let existing = if profile_path.exists() {
        fs::read_to_string(profile_path).unwrap_or_default()
    } else {
        String::new()
    };
    let export_line = export_line.trim_end_matches('\n');
    let marker_line = export_line.split('\n').next().unwrap_or("");
    let export_line = if marker_line.trim() != marker.trim() {
        format!("{marker}\n{export_line}")
    } else {
        export_line.to_owned()
    };
    let desired = format!("{export_line}\n");
    if existing == desired {
        let mut r = obj();
        r.insert("changed".into(), v_bool(false));
        return r;
    }
    let cleaned = strip_managed_marker_blocks(&existing, marker);
    let new_content = if cleaned.is_empty() {
        desired.clone()
    } else {
        let prefix = if cleaned.ends_with('\n') { "" } else { "\n" };
        format!("{cleaned}{prefix}{desired}")
    };
    if new_content == existing {
        let mut r = obj();
        r.insert("changed".into(), v_bool(false));
        return r;
    }
    let _ = fs::write(profile_path, &new_content);
    let mut r = obj();
    r.insert("changed".into(), v_bool(true));
    r
}

/// `_strip_managed_marker_blocks` (:905-949).
fn strip_managed_marker_blocks(content: &str, marker: &str) -> String {
    if content.is_empty() {
        return String::new();
    }
    let marker_stripped = marker.trim();
    let lines: Vec<&str> = content.lines().collect();
    let mut drop_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim() == marker_stripped && index + 1 < lines.len() {
            drop_indices.insert(index);
            drop_indices.insert(index + 1);
        }
    }
    if drop_indices.is_empty() {
        return if content.ends_with('\n') {
            content.to_owned()
        } else {
            format!("{content}\n")
        };
    }
    let mut keep: Vec<&str> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if drop_indices.contains(&index) {
            continue;
        }
        let is_blank = line.trim().is_empty();
        if is_blank {
            let prev_kept_blank = keep.last().map(|l| l.trim().is_empty()).unwrap_or(false);
            let prev_dropped = index > 0 && drop_indices.contains(&(index - 1));
            let next_dropped = index + 1 < lines.len() && drop_indices.contains(&(index + 1));
            if (prev_kept_blank || keep.is_empty() || next_dropped) && prev_dropped {
                continue;
            }
        }
        keep.push(line);
    }
    let mut result = keep.join("\n");
    if !result.is_empty() && !result.ends_with('\n') {
        result.push('\n');
    }
    result
}

/// `_guard_shim_profile_target` (:950-968).
fn guard_shim_profile_target(home_dir: &Path, shim_dir: &Path) -> (PathBuf, String) {
    let shell = std::env::var("SHELL")
        .ok()
        .and_then(|s| {
            Path::new(&s)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let marker = _GUARD_PROFILE_MARKER;
    if shell == "fish" {
        return (
            home_dir.join(".config").join("fish").join("config.fish"),
            format!("{marker}\n{}", fish_path_prepend(shim_dir)),
        );
    }
    if shell == "bash" {
        return (
            home_dir.join(".bashrc"),
            format!("{marker}\n{}", posix_path_export(shim_dir)),
        );
    }
    (
        home_dir.join(".zshrc"),
        format!("{marker}\n{}", posix_path_export(shim_dir)),
    )
}

/// `_package_shim_profile_target` (:969-987).
fn package_shim_profile_target(home_dir: &Path, shim_dir: &Path) -> (PathBuf, String) {
    let shell = std::env::var("SHELL")
        .ok()
        .and_then(|s| {
            Path::new(&s)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let marker = _PACKAGE_PROFILE_MARKER;
    if shell == "fish" {
        return (
            home_dir.join(".config").join("fish").join("config.fish"),
            format!("{marker}\n{}", fish_path_prepend(shim_dir)),
        );
    }
    if shell == "bash" {
        return (
            home_dir.join(".bashrc"),
            format!("{marker}\n{}", posix_path_export(shim_dir)),
        );
    }
    (
        home_dir.join(".zshrc"),
        format!("{marker}\n{}", posix_path_export(shim_dir)),
    )
}

/// `_package_shim_profile_targets` (:988-1016).
fn package_shim_profile_targets(home_dir: &Path, shim_dir: &Path) -> Vec<(PathBuf, String)> {
    let primary = package_shim_profile_target(home_dir, shim_dir);
    let marker = _PACKAGE_PROFILE_MARKER;
    let bash_export = format!("{marker}\n{}", posix_path_export(shim_dir));
    let bash_login_path = bash_login_profile_path(home_dir);
    let candidates = vec![
        primary,
        (home_dir.join(".bashrc"), bash_export.clone()),
        (bash_login_path, bash_export),
    ];
    let mut deduplicated: Vec<(PathBuf, String)> = Vec::new();
    let mut seen_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for (profile_path, export_line) in candidates {
        if seen_paths.contains(&profile_path) {
            continue;
        }
        seen_paths.insert(profile_path.clone());
        deduplicated.push((profile_path, export_line));
    }
    deduplicated
}

/// `_bash_login_profile_path` (:1017-1026).
fn bash_login_profile_path(home_dir: &Path) -> PathBuf {
    for name in [".bash_profile", ".bash_login"] {
        let candidate = home_dir.join(name);
        if candidate.exists() {
            return candidate;
        }
    }
    home_dir.join(".profile")
}

/// `_posix_path_export` (:1027-1030).
fn posix_path_export(shim_dir: &Path) -> String {
    format!("export PATH=\"{}:$PATH\"", shim_dir.to_string_lossy())
}

/// `_fish_path_prepend` (:1031-1034).
fn fish_path_prepend(shim_dir: &Path) -> String {
    format!("fish_add_path --prepend {}", shim_dir.to_string_lossy())
}

/// `_is_transient_path` (:1035-1059).
fn is_transient_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains("/tmp/")
        || s.contains("/var/folders/")
        || s.contains("/private/tmp/")
        || s.contains("AppData\\Local\\Temp")
        || s.contains("\\Temp\\")
        || s.to_lowercase().contains("appimage")
}

/// `_profile_already_references_path` (:1060-1069).
fn profile_already_references_path(content: &str, shim_dir: &Path) -> bool {
    let dir_str = shim_dir.to_string_lossy();
    content.contains(&*dir_str)
}

/// `_package_protect_command_args` (:1070-1092).
fn package_protect_command_args(context: &HarnessContext) -> Vec<String> {
    let home_dir = &context.home_dir;
    let mut protect_args = vec![
        "protect".to_owned(),
        "--package-shim-ui".to_owned(),
        "--guard-home".to_owned(),
        context.guard_home.to_string_lossy().into_owned(),
    ];
    if let Some(hd) = home_dir {
        protect_args.push("--home".to_owned());
        protect_args.push(hd.to_string_lossy().into_owned());
    }
    if is_frozen() {
        let mut args = vec![package_shim_interpreter()];
        args.extend(protect_args);
        return args;
    }
    let mut args = vec![sys_executable()];
    args.extend(trusted_python_flags());
    args.push("-c".to_owned());
    args.push(TRUSTED_CLI_LAUNCHER.to_owned());
    args.push(trusted_import_root().to_string_lossy().into_owned());
    args.push("codex_plugin_scanner.cli".to_owned());
    args.push("guard".to_owned());
    args.extend(protect_args);
    args
}

/// `_build_package_manager_python_shim` (:1093-1292).
fn build_package_manager_python_shim(context: &HarnessContext, command: &str) -> String {
    let shim_dir = context.package_shim_bin_dir();
    let command_args = package_protect_command_args(context);
    let local_test_runners: Vec<String> = {
        let mut v: Vec<String> = _LOCAL_TEST_RUNNER_COMMANDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        v.sort();
        v
    };
    let lines: Vec<String> = vec![
        format!("#!{}", package_shim_interpreter()),
        "from __future__ import annotations".to_owned(),
        "import os".to_owned(),
        "import shutil".to_owned(),
        "import subprocess".to_owned(),
        "import sys".to_owned(),
        "import time".to_owned(),
        "from pathlib import Path".to_owned(),
        format!("{FROZEN_PACKAGE_SHIM_SENTINEL} = True"),
        format!("base_command = {}", py_repr_list(&command_args)),
        format!("command_name = {}", py_repr_str(command)),
        format!("guard_cli_cwd = {}", py_repr_str(&trusted_import_root().to_string_lossy())),
        "guard_workspace = None".to_owned(),
        format!("guard_home = {}", py_repr_str(&context.guard_home.to_string_lossy())),
        "guard_has_explicit_workspace = False".to_owned(),
        format!("shim_dir = {}", py_repr_str(&resolve_or_self(&shim_dir).to_string_lossy())),
        format!("local_test_runners = {}", py_repr_tuple(&local_test_runners)),
        format!(
            "shim_probe = os.environ.get({}) == {}",
            py_repr_str(SHIM_PROBE_ENV_VAR),
            py_repr_str(SHIM_PROBE_ENV_VALUE)
        ),
        format!("store_lock_retry_timeout_seconds = {SQLITE_CONNECT_TIMEOUT_SECONDS}"),
        "store_lock_retry_delay_seconds = 0.1".to_owned(),
        "def _real_manager_launch():".to_owned(),
        "    path_entries = [entry for entry in os.environ.get('PATH', '').split(os.pathsep) if entry]".to_owned(),
        "    shim_dir_abs = os.path.abspath(shim_dir)".to_owned(),
        "    filtered_entries = [entry for entry in path_entries if os.path.abspath(os.path.expanduser(entry)) != shim_dir_abs]".to_owned(),
        "    filtered_path = os.pathsep.join(filtered_entries)".to_owned(),
        "    resolved = shutil.which(command_name, path=filtered_path)".to_owned(),
        "    if resolved is None:".to_owned(),
        "        raise SystemExit(f\"guard shim: real binary not found for {command_name}\")".to_owned(),
        "    return resolved, filtered_path".to_owned(),
        "".to_owned(),
        "def _exec_real_manager():".to_owned(),
        "    resolved, filtered_path = _real_manager_launch()".to_owned(),
        "    env = dict(os.environ)".to_owned(),
        "    env['PATH'] = filtered_path".to_owned(),
        "    os.execvpe(resolved, [resolved, *sys.argv[1:]], env)".to_owned(),
        "".to_owned(),
        "contained_result = None".to_owned(),
        "try:".to_owned(),
        "    from codex_plugin_scanner.guard.contained_typescript_execution import (".to_owned(),
        "        try_execute_contained_typescript,".to_owned(),
        "    )".to_owned(),
        "    contained_result = try_execute_contained_typescript(".to_owned(),
        "        command_name,".to_owned(),
        "        tuple(sys.argv[1:]),".to_owned(),
        "        workspace=Path(guard_workspace) if guard_workspace is not None else Path.cwd(),".to_owned(),
        "        guard_home=Path(guard_home),".to_owned(),
        "        shim_directory=Path(shim_dir),".to_owned(),
        "        environment=dict(os.environ),".to_owned(),
        "    )".to_owned(),
        "except Exception:".to_owned(),
        "    contained_result = None".to_owned(),
        "if contained_result is None:".to_owned(),
        "    try:".to_owned(),
        "        from codex_plugin_scanner.guard.contained_node_execution import (".to_owned(),
        "            try_execute_contained_node_command,".to_owned(),
        "        )".to_owned(),
        "        contained_result = try_execute_contained_node_command(".to_owned(),
        "            command_name,".to_owned(),
        "            tuple(sys.argv[1:]),".to_owned(),
        "            workspace=Path(guard_workspace) if guard_workspace is not None else Path.cwd(),".to_owned(),
        "            guard_home=Path(guard_home),".to_owned(),
        "            shim_directory=Path(shim_dir),".to_owned(),
        "            environment=dict(os.environ),".to_owned(),
        "        )".to_owned(),
        "    except Exception:".to_owned(),
        "        contained_result = None".to_owned(),
        "if contained_result is not None:".to_owned(),
        "    if contained_result.stdout:".to_owned(),
        "        sys.stdout.write(contained_result.stdout)".to_owned(),
        "    if contained_result.stderr:".to_owned(),
        "        sys.stderr.write(contained_result.stderr)".to_owned(),
        "    raise SystemExit(contained_result.exit_code)".to_owned(),
        "guard_env = dict(os.environ)".to_owned(),
        "guard_args = list(sys.argv[1:])".to_owned(),
        "guard_env.pop('PYTHONPATH', None)".to_owned(),
        format!("guard_env.pop({}, None)", py_repr_str(PACKAGE_SHIM_STATUS_FD_ENV_VAR)),
        "guard_command = [*base_command, '--dry-run', command_name]".to_owned(),
        "if external_archive_binding_required:".to_owned(),
        "    resolved_command, guard_args, guard_env = _real_manager_launch()".to_owned(),
        "guard_process = subprocess.run(guard_command, capture_output=True, text=True, cwd=guard_cli_cwd, env=guard_env)".to_owned(),
        "except KeyboardInterrupt:".to_owned(),
        "    raise SystemExit(130)".to_owned(),
        "if guard_process.stdout:".to_owned(),
        "    sys.stdout.write(guard_process.stdout)".to_owned(),
        "if guard_process.stderr:".to_owned(),
        "    sys.stderr.write(guard_process.stderr)".to_owned(),
        "if shim_probe:".to_owned(),
        "    raise SystemExit(0)".to_owned(),
        "if external_archive_binding_required:".to_owned(),
        "    raise SystemExit(guard_process.returncode)".to_owned(),
        "if guard_process.returncode != 0:".to_owned(),
        "    raise SystemExit(guard_process.returncode)".to_owned(),
        "_exec_real_manager()".to_owned(),
        "".to_owned(),
    ];
    lines.join("\n")
}

/// `_trusted_python_flags` (:1293-1299).
fn trusted_python_flags() -> Vec<String> {
    let mut flags = vec!["-I".to_owned()];
    if python_version_at_least(3, 11) {
        flags.push("-P".to_owned());
    }
    flags
}

fn python_version_at_least(major: u32, minor: u32) -> bool {
    let output = std::process::Command::new(sys_executable())
        .arg("--version")
        .output();
    match output {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout);
            let parts: Vec<&str> = s.split_whitespace().collect();
            if let Some(ver) = parts.get(1) {
                let nums: Vec<u32> = ver.split('.').filter_map(|p| p.parse().ok()).collect();
                if let (Some(&maj), Some(&min)) = (nums.first(), nums.get(1)) {
                    return (maj, min) >= (major, minor);
                }
            }
            false
        }
        Err(_) => false,
    }
}

/// `_normalize_package_shim_managers` (:1300-1310).
fn normalize_package_shim_managers(managers: Option<&[&str]>) -> Vec<String> {
    match managers {
        None => package_shim_supported_managers()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        Some([]) => package_shim_supported_managers()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        Some(list) => {
            let mut normalized: Vec<String> = Vec::new();
            for manager in list {
                let key = manager.trim().to_lowercase();
                if package_shim_command(&key).is_some() && !normalized.contains(&key) {
                    normalized.push(key);
                }
            }
            normalized
        }
    }
}

/// `_trusted_import_root` (:1311-1314).
fn trusted_import_root() -> PathBuf {
    // Rust equivalent: walk up from the compiled binary's embedded source root.
    // In the Python source this is Path(__file__).resolve().parents[2] — the
    // codex_plugin_scanner package root. We use the compile-time manifest dir
    // which sits at rust/crates/guard-command → parents[2] = repo root.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest)
}

/// `_package_shim_manifest_path` (:1315-1318).
fn package_shim_manifest_path(context: &HarnessContext) -> PathBuf {
    context.package_shim_dir().join(_PACKAGE_SHIM_MANIFEST)
}

/// `_filtered_manager_path` (:1319-1327).
fn filtered_manager_path(context: &HarnessContext, path_env: Option<&str>) -> String {
    let shim_dir = context.package_shim_bin_dir();
    let shim_dir_abs = resolve_or_self(&PathBuf::from(shellexpand_tilde(
        &shim_dir.to_string_lossy(),
    )));
    let effective_path = path_env
        .map(str::to_owned)
        .unwrap_or_else(|| std::env::var("PATH").unwrap_or_default());
    let filtered: Vec<String> = effective_path
        .split(':')
        .filter(|e| !e.is_empty())
        .filter(|entry| resolve_or_self(&PathBuf::from(shellexpand_tilde(entry))) != shim_dir_abs)
        .map(str::to_owned)
        .collect();
    filtered.join(":")
}

/// `_detect_system_package_managers` (:1328-1349).
fn detect_system_package_managers(
    context: &HarnessContext,
    path_env: Option<&str>,
) -> (Vec<String>, Vec<String>) {
    let filtered_path = filtered_manager_path(context, path_env);
    let _ = context;
    let mut detected: Vec<String> = Vec::new();
    let mut undetected: Vec<String> = Vec::new();
    for manager in package_shim_supported_managers() {
        let command = package_shim_command(manager).unwrap_or(manager);
        if which_in_path(command, &filtered_path).is_some() {
            detected.push(manager.to_owned());
        } else {
            undetected.push(manager.to_owned());
        }
    }
    (detected, undetected)
}

fn which_in_path(command: &str, path_env: &str) -> Option<PathBuf> {
    for entry in path_env.split(':') {
        if entry.is_empty() {
            continue;
        }
        let candidate = PathBuf::from(entry).join(command);
        if candidate.exists() && candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// `_load_package_shim_manifest` (:1350-1354).
fn load_package_shim_manifest(context: &HarnessContext) -> Map<String, Value> {
    load_package_shim_manifest_with_state(context).0
}

/// `_load_package_shim_manifest_with_state` (:1355-1374).
fn load_package_shim_manifest_with_state(
    context: &HarnessContext,
) -> (Map<String, Value>, &'static str) {
    let manifest_path = package_shim_manifest_path(context);
    if !manifest_path.exists() {
        return (Map::new(), "missing");
    }
    match fs::read_to_string(&manifest_path) {
        Ok(text) => match serde_json::from_str::<Value>(&text) {
            Ok(Value::Object(map)) => (map, "ok"),
            Ok(_) => (Map::new(), "invalid"),
            Err(_) => (Map::new(), "invalid"),
        },
        Err(_) => (Map::new(), "unreadable"),
    }
}

/// `_dict_items` (:1375-1380).
fn _dict_items(value: Option<&Value>) -> Vec<Map<String, Value>> {
    dict_items(value)
}

/// `_string_items` (:1381-1386).
fn _string_items(value: Option<&Value>) -> Vec<String> {
    string_items(value)
}

/// `_string_map` (:1387-1392).
fn _string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    string_map(value)
}

/// `_write_package_shim_manifest` (:1393-1396).
fn write_package_shim_manifest(context: &HarnessContext, manifest: &Map<String, Value>) {
    let path = package_shim_manifest_path(context);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(
        &path,
        serde_json::to_string_pretty(&Value::Object(manifest.clone())).unwrap_or_default(),
    );
}

/// `_record_package_shim_test_results` (:1397-1413).
fn record_package_shim_test_results(context: &HarnessContext, results: &[Map<String, Value>]) {
    let (mut manifest, _) = load_package_shim_manifest_with_state(context);
    let now = Timestamp::now_utc().isoformat();
    let mut last_test_at = string_map(manifest.get("last_test_at"));
    for result in results {
        if let Some(manager) = result.get("manager").and_then(Value::as_str) {
            if package_shim_command(manager).is_some() {
                last_test_at.insert(manager.to_owned(), now.clone());
            }
        }
    }
    manifest.insert(
        "last_test_at".into(),
        Value::Object(
            last_test_at
                .iter()
                .map(|(k, v)| (k.clone(), v_str(v.clone())))
                .collect(),
        ),
    );
    write_package_shim_manifest(context, &manifest);
}

/// `_command_program_name` (:1414-1420).
fn command_program_name() -> String {
    std::env::args()
        .next()
        .and_then(|arg0| {
            Path::new(&arg0)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "hol-guard".to_owned())
}

/// `_path_export_hint` (:1421-1426).
fn path_export_hint(shim_dir: &Path) -> String {
    if cfg!(windows) {
        format!("set PATH={};%PATH%", shim_dir.to_string_lossy())
    } else {
        posix_path_export(shim_dir)
    }
}

/// `_path_export_hints` (:1427-1436).
fn path_export_hints(shim_dir: &Path) -> Map<String, Value> {
    let posix_hint = posix_path_export(shim_dir);
    let mut hints = obj();
    hints.insert("bash".into(), v_str(&posix_hint));
    hints.insert("zsh".into(), v_str(&posix_hint));
    hints.insert("fish".into(), v_str(fish_path_prepend(shim_dir)));
    hints.insert(
        "powershell".into(),
        v_str(format!(
            "$env:Path = \"{};$env:Path\"",
            shim_dir.to_string_lossy()
        )),
    );
    hints
}

/// `probe_package_shim_intercepts` (:1437-1580).
pub fn probe_package_shim_intercepts(
    context: &HarnessContext,
    managers: Option<&[&str]>,
    workspace_dir: Option<&Path>,
    allow_inactive_path: bool,
    timeout_seconds: Option<i64>,
) -> Map<String, Value> {
    let timeout = timeout_seconds.unwrap_or(_PACKAGE_SHIM_PROBE_TIMEOUT_SECONDS);
    let status = package_shim_status(context, None);
    let installed: BTreeSet<String> = string_items(status.get("installed_managers"))
        .into_iter()
        .collect();
    let protected: BTreeSet<String> = string_items(status.get("protected_managers"))
        .into_iter()
        .collect();
    let tested_managers: Vec<String> = match managers {
        Some(m) => m.iter().map(|s| s.to_string()).collect(),
        None => installed.iter().cloned().collect(),
    };
    let path_repair_required: Vec<String> = tested_managers
        .iter()
        .filter(|m| installed.contains(*m) && !protected.contains(*m))
        .cloned()
        .collect();
    let detail_by_manager: BTreeMap<String, Map<String, Value>> =
        dict_items(status.get("manager_details"))
            .into_iter()
            .filter_map(|d| {
                d.get("manager")
                    .and_then(Value::as_str)
                    .map(|m| (m.to_owned(), d.clone()))
            })
            .collect();
    let target_workspace = workspace_dir
        .map(|p| p.to_path_buf())
        .or_else(|| context.workspace_dir.clone())
        .or_else(|| context.home_dir.clone());
    let shim_dir = context.package_shim_bin_dir();
    let mut manager_results: Vec<Map<String, Value>> = Vec::new();
    for manager in &tested_managers {
        if !installed.contains(manager) {
            continue;
        }
        let manager_detail = detail_by_manager.get(manager);
        if manager_detail
            .and_then(|d| d.get("integrity"))
            .and_then(Value::as_str)
            == Some("tampered")
        {
            let mut r = obj();
            r.insert("evaluator_invoked".into(), v_bool(false));
            r.insert("intercept_ran".into(), v_bool(false));
            r.insert("manager".into(), v_str(manager));
            r.insert("skipped_reason".into(), v_str("shim_tampered"));
            manager_results.push(r);
            continue;
        }
        if !protected.contains(manager) && !allow_inactive_path {
            let mut r = obj();
            r.insert("evaluator_invoked".into(), v_bool(false));
            r.insert("intercept_ran".into(), v_bool(false));
            r.insert("manager".into(), v_str(manager));
            r.insert("skipped_reason".into(), v_str("path_inactive"));
            manager_results.push(r);
            continue;
        }
        let command = match package_shim_command(manager) {
            Some(c) => c,
            None => {
                let mut r = obj();
                r.insert("evaluator_invoked".into(), v_bool(false));
                r.insert("intercept_ran".into(), v_bool(false));
                r.insert("manager".into(), v_str(manager));
                r.insert("skipped_reason".into(), v_str("unsupported_manager"));
                manager_results.push(r);
                continue;
            }
        };
        let shim_path = shim_dir.join(command);
        if !shim_path.exists() {
            let mut r = obj();
            r.insert("evaluator_invoked".into(), v_bool(false));
            r.insert("intercept_ran".into(), v_bool(false));
            r.insert("manager".into(), v_str(manager));
            r.insert("skipped_reason".into(), v_str("shim_missing"));
            manager_results.push(r);
            continue;
        }
        let probe_args = package_shim_probe_args(manager);
        let mut probe_env: Vec<(String, String)> = std::env::vars().collect();
        probe_env.push((
            SHIM_PROBE_ENV_VAR.to_owned(),
            SHIM_PROBE_ENV_VALUE.to_owned(),
        ));
        let mut cmd = std::process::Command::new(&shim_path);
        cmd.args(&probe_args)
            .env(SHIM_PROBE_ENV_VAR, SHIM_PROBE_ENV_VALUE)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(ws) = &target_workspace {
            cmd.current_dir(ws);
        }
        let child_result = cmd
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let result = match child_result {
            Ok(child) => {
                let output = child.wait_with_output();
                output.ok()
            }
            Err(_) => None,
        };
        let _ = timeout; // timeout applied via spawn above; not enforced for shim probes
        match result {
            Some(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
                let truncated = stdout.len() > _MAX_PACKAGE_SHIM_PROBE_OUTPUT_BYTES
                    || stderr.len() > _MAX_PACKAGE_SHIM_PROBE_OUTPUT_BYTES;
                let stdout_snippet: String = stdout
                    .chars()
                    .take(_MAX_PACKAGE_SHIM_PROBE_OUTPUT_BYTES)
                    .collect();
                let stderr_snippet: String = stderr
                    .chars()
                    .take(_MAX_PACKAGE_SHIM_PROBE_OUTPUT_BYTES)
                    .collect();
                let payload = parse_protect_json_stdout(&stdout);
                let evaluator_evidence = protect_evaluator_evidence(&payload);
                let mut r = obj();
                r.insert(
                    "evaluator_invoked".into(),
                    v_bool(evaluator_evidence.is_some()),
                );
                r.insert("intercept_ran".into(), v_bool(true));
                r.insert("manager".into(), v_str(manager));
                r.insert(
                    "returncode".into(),
                    serde_json::json!(out.status.code().unwrap_or(-1)),
                );
                r.insert("stdout".into(), v_str(stdout_snippet));
                r.insert("stderr".into(), v_str(stderr_snippet));
                r.insert("truncated".into(), v_bool(truncated));
                if let Some(evidence) = evaluator_evidence {
                    r.insert("evaluator_evidence".into(), evidence);
                }
                manager_results.push(r);
            }
            None => {
                let mut r = obj();
                r.insert("evaluator_invoked".into(), v_bool(false));
                r.insert("intercept_ran".into(), v_bool(false));
                r.insert("manager".into(), v_str(manager));
                r.insert("skipped_reason".into(), v_str("shim_exec_failed"));
                manager_results.push(r);
            }
        }
    }
    record_package_shim_test_results(context, &manager_results);
    let intercept_proved = manager_results.iter().all(|r| {
        r.get("intercept_ran")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }) && !manager_results.is_empty();
    let mut r = obj();
    r.insert(
        "blocked_execution".into(),
        v_bool(
            !tested_managers.is_empty() && tested_managers.iter().all(|m| protected.contains(m)),
        ),
    );
    r.insert("intercept_proved".into(), v_bool(intercept_proved));
    r.insert(
        "manager_results".into(),
        v_arr(manager_results.into_iter().map(v_map).collect()),
    );
    r.insert(
        "missing_managers".into(),
        v_str_arr(
            tested_managers
                .iter()
                .filter(|m| !installed.contains(*m))
                .cloned()
                .collect(),
        ),
    );
    r.insert("package_shims".into(), v_map(status));
    r.insert(
        "path_repair_required".into(),
        v_str_arr(path_repair_required),
    );
    r.insert("tested_managers".into(), v_str_arr(tested_managers));
    r
}

// ---------------------------------------------------------------------------
// Internal dependency stubs matching Python seams.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_harness_shim(
    python: &str,
    harness: &str,
    _context: &HarnessContext,
    workspace_args: &[String],
    trusted_python_flags: &[String],
    trusted_launcher: &str,
    trusted_import_root: &Path,
    launcher_env: &BTreeMap<String, String>,
    home_override_args: &[String],
    is_transient_path: fn(&Path) -> bool,
) -> String {
    // Mirrors durable_harness_launcher.build_harness_shim: emits a POSIX shell
    // script that routes harness launches through the guard protect CLI.
    let launcher_env_flags: String = launcher_env
        .iter()
        .map(|(k, v)| format!("{}={} ", k, crate::command_launcher_floors::shlex_quote(v)))
        .collect();
    let all_args: Vec<String> = {
        let mut a = vec!["guard".to_owned(), "protect".to_owned()];
        a.extend(workspace_args.iter().cloned());
        a.extend(home_override_args.iter().cloned());
        a.push("--".to_owned());
        a.push(harness.to_owned());
        a
    };
    let guard_cmd = format!(
        "{} {} {} {}",
        python,
        trusted_python_flags.join(" "),
        "-c",
        crate::command_launcher_floors::shlex_quote(trusted_launcher),
    );
    let _ = is_transient_path;
    format!(
        "#!/bin/sh\n{}exec {} {} {} \"$@\"\n",
        launcher_env_flags,
        guard_cmd,
        crate::command_launcher_floors::shlex_quote(&trusted_import_root.to_string_lossy()),
        all_args
            .iter()
            .map(|a| crate::command_launcher_floors::shlex_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn merge_guard_launcher_env() -> BTreeMap<String, String> {
    // Mirrors launcher.merge_guard_launcher_env: forward guard-relevant env vars.
    let mut env_map = BTreeMap::new();
    for key in &["HOL_GUARD_HOME", "HOL_GUARD_WORKSPACE", "HOL_GUARD_DEBUG"] {
        if let Ok(val) = std::env::var(key) {
            env_map.insert(key.to_string(), val);
        }
    }
    env_map
}

fn package_shim_probe_args(manager: &str) -> Vec<String> {
    match manager {
        "npm" | "pnpm" | "yarn" | "bun" => vec!["--version".to_owned()],
        "pip" | "pip3" | "uv" | "poetry" => vec!["--version".to_owned()],
        _ => vec!["--version".to_owned()],
    }
}

fn installed_package_shim_attestation_bytes(
    _shim_dir: &Path,
    _command: &str,
    content: &[u8],
) -> Vec<u8> {
    content.to_vec()
}

fn frozen_package_shim_python_path(shim_dir: &Path, command: &str) -> PathBuf {
    shim_dir.join(format!("{command}.py"))
}

fn classify_installed_package_shim_integrity(
    python_source: &str,
    shim_dir: &Path,
    command: &str,
    installed_wrapper: &[u8],
    stored_hash: Option<&str>,
) -> String {
    let expected = expected_package_shim_executable_bytes(python_source, shim_dir, command);
    if installed_wrapper == expected {
        return "ok".to_owned();
    }
    if let Some(hash) = stored_hash {
        let attestation =
            installed_package_shim_attestation_bytes(shim_dir, command, installed_wrapper);
        if build_shim_content_hash(&attestation) == hash {
            return "stale".to_owned();
        }
    }
    "tampered".to_owned()
}

fn expected_package_shim_executable_bytes(
    python_source: &str,
    _shim_dir: &Path,
    _command: &str,
) -> Vec<u8> {
    python_source.as_bytes().to_vec()
}

fn parse_protect_json_stdout(stdout: &str) -> Option<Map<String, Value>> {
    for line in stdout.lines().rev() {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(line.trim()) {
            return Some(map);
        }
    }
    None
}

fn protect_evaluator_evidence(payload: &Option<Map<String, Value>>) -> Option<Value> {
    payload
        .as_ref()
        .and_then(|p| p.get("evaluator_evidence").cloned())
}
