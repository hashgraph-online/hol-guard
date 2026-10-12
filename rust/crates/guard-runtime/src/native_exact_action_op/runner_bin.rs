//! Content-hashed project-local binary evidence for package-runner commands.
//!
//! A runner command (`npx wrangler`) is bound to the project's
//! `node_modules/.bin` binary only when the package-intent parser proves the
//! bin resolves locally. Registry and cache fetches never carry a persistent allow.

use std::io::Read;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use super::context::{Ctx, EvidenceFile};
use super::fs_path;
use super::launcher_sets::is_mutable_launcher;

pub(crate) const LOCAL_BIN_RUNNERS: [&str; 6] = ["npx", "bunx", "pnpm", "pnpx", "yarn", "npm"];
const PRETARGET_OPTIONS: [&str; 2] = ["-y", "--yes"];
const EXEC_SUBCOMMANDS: [&str; 2] = ["exec", "x"];
const EXEC_SUBCOMMAND_RUNNERS: [&str; 3] = ["npm", "pnpm", "yarn"];
const MAX_PACKAGE_MANIFEST_BYTES: u64 = 1_048_576;

pub(crate) fn package_name_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\z").expect("static pattern")
    })
}

pub(crate) enum Manifest {
    Absent,
    Unreadable,
    Data(Value),
}

pub(crate) fn read_manifest(path: &str) -> Manifest {
    if !fs_path::is_file(path) {
        return Manifest::Absent;
    }
    let Ok(meta) = std::fs::metadata(path) else {
        return Manifest::Unreadable;
    };
    if meta.len() > MAX_PACKAGE_MANIFEST_BYTES {
        return Manifest::Unreadable;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Manifest::Unreadable;
    };
    serde_json::from_str(&text).map_or(Manifest::Unreadable, Manifest::Data)
}

/// The bin a runner launches, or `None` for any selector form.
pub(crate) fn runner_target<'a>(runner: &str, arguments: &'a [String]) -> Option<&'a str> {
    let mut exec_allowed = EXEC_SUBCOMMAND_RUNNERS.contains(&runner);
    for argument in arguments {
        if argument == "--" || PRETARGET_OPTIONS.contains(&argument.as_str()) {
            continue;
        }
        if argument.starts_with('-') {
            return None;
        }
        if exec_allowed && EXEC_SUBCOMMANDS.contains(&argument.as_str()) {
            exec_allowed = false;
            continue;
        }
        return Some(argument);
    }
    None
}

fn is_bin_shim(resolved: &str) -> bool {
    let parent = fs_path::parent(resolved);
    fs_path::name(&parent) == ".bin" && fs_path::name(&fs_path::parent(&parent)) == "node_modules"
}

fn package_dir(node_modules: &str, package_name: &str) -> String {
    package_name
        .split('/')
        .fold(fs_path::norm(node_modules), |dir, part| {
            fs_path::join(&dir, part)
        })
}

fn manifest_version(data: &Manifest, package_name: &str) -> Option<String> {
    let Manifest::Data(Value::Object(map)) = data else {
        return None;
    };
    if map.get("name").and_then(Value::as_str) != Some(package_name) {
        return None;
    }
    map.get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .map(str::to_owned)
}

fn shim_package_version(node_modules: &str, package_name: &str) -> Option<String> {
    if !package_name_pattern().is_match(package_name) {
        return None;
    }
    let manifest = fs_path::join(&package_dir(node_modules, package_name), "package.json");
    manifest_version(&read_manifest(&manifest), package_name)
}

/// The installed version of the package that owns the resolved bin.
fn installed_package_version(resolved: &str, package_name: &str) -> Option<String> {
    if package_name.is_empty() {
        return None;
    }
    if is_bin_shim(resolved) {
        // npm on Windows and pnpm write regular-file shims instead of symlinks.
        return shim_package_version(&fs_path::parent(&fs_path::parent(resolved)), package_name);
    }
    for parent in fs_path::parents(resolved) {
        if fs_path::name(&parent) == "node_modules" {
            return None;
        }
        match read_manifest(&fs_path::join(&parent, "package.json")) {
            Manifest::Unreadable => return None,
            data @ Manifest::Data(_) => {
                if let Manifest::Data(Value::Object(map)) = &data {
                    if map.get("name").and_then(Value::as_str) == Some(package_name) {
                        return manifest_version(&data, package_name);
                    }
                }
            }
            Manifest::Absent => {}
        }
    }
    None
}

fn sha256_of_file(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut chunk).ok()?;
        if read == 0 {
            return Some(hex::encode(hasher.finalize()));
        }
        hasher.update(&chunk[..read]);
    }
}

/// Hash the package bin script a `node_modules/.bin` shim launches.
fn shim_bin_target(node_modules: &str, package_name: &str, executable: &str) -> Option<Value> {
    if !package_name_pattern().is_match(package_name) {
        return None;
    }
    let dir = package_dir(node_modules, package_name);
    let Manifest::Data(Value::Object(map)) = read_manifest(&fs_path::join(&dir, "package.json"))
    else {
        return None;
    };
    if map.get("name").and_then(Value::as_str) != Some(package_name) {
        return None;
    }
    let entry = match map.get("bin")? {
        Value::String(text) if executable == package_name.rsplit('/').next().unwrap_or("") => {
            text.as_str()
        }
        Value::Object(bins) => bins.get(executable).and_then(Value::as_str)?,
        _ => return None,
    };
    if entry.trim().is_empty() {
        return None;
    }
    let root = fs_path::resolve_strict(&dir)?;
    let script = fs_path::resolve_strict(&fs_path::join(&root, entry))?;
    if !fs_path::is_inside(&script, &root) || !fs_path::is_file(&script) {
        return None;
    }
    let digest = sha256_of_file(&script)?;
    Some(json!({"resolved_path": script, "content_hash": format!("sha256:{digest}")}))
}

fn file_hashes(entries: &[EvidenceFile]) -> Vec<Value> {
    entries
        .iter()
        .map(|entry| json!({"path": entry.path, "status": entry.status, "content_hash": entry.content_hash}))
        .collect()
}

/// `runner_local_bin`: content-hashed local-bin evidence for a runner command.
/// `reject_mutable` refuses targets that are themselves mutable launchers.
pub(crate) fn runner_local_bin(
    command: &str,
    runner: &str,
    arguments: &[String],
    cwd: &str,
    ctx: &Ctx,
    reject_mutable: bool,
) -> Option<Value> {
    ctx.check().ok()?;
    let executions = ctx
        .engines
        .local_executions(command, cwd, ctx.home, ctx.env)?;
    let [evidence] = executions.as_slice() else {
        return None;
    };
    let (local, manager) = (
        evidence.local_executable.as_ref()?,
        evidence.manager.as_ref()?,
    );
    if evidence.manager_is_guard_shim {
        return None;
    }
    let resolved = local
        .resolved_path
        .as_deref()
        .filter(|path| !path.is_empty())?;
    let content_hash = local
        .content_hash
        .as_deref()
        .filter(|hash| !hash.is_empty())?;
    if local.status != "available" {
        return None;
    }
    // A versioned or aliased spec can make the runner fetch a different
    // release than the local bin, so only the bare bin name binds.
    let target = runner_target(runner, arguments)?;
    if Some(target) != evidence.executable_name.as_deref()
        || (reject_mutable && is_mutable_launcher(&target.to_lowercase()))
    {
        return None;
    }
    let package_name = evidence.package_name.as_deref().unwrap_or("");
    let version = installed_package_version(resolved, package_name)?;
    let bin_target = if is_bin_shim(resolved) {
        // A shim only launches the package's bin script: bind that script too.
        Some(shim_bin_target(
            &fs_path::parent(&fs_path::parent(resolved)),
            package_name,
            target,
        )?)
    } else {
        None
    };
    let mut record = Map::new();
    record.insert("package_name".into(), json!(evidence.package_name));
    record.insert("executable_name".into(), json!(evidence.executable_name));
    record.insert("installed_version".into(), json!(version));
    record.insert("resolved_path".into(), json!(resolved));
    record.insert("content_hash".into(), json!(content_hash));
    record.insert(
        "manager".into(),
        json!({"resolved_path": manager.resolved_path, "content_hash": manager.content_hash}),
    );
    record.insert(
        "manifests".into(),
        Value::Array(file_hashes(&evidence.manifests)),
    );
    record.insert(
        "lockfiles".into(),
        Value::Array(file_hashes(&evidence.lockfiles)),
    );
    if let Some(bin_target) = bin_target {
        record.insert("bin_target".into(), bin_target);
    }
    Some(Value::Object(record))
}
