//! The Guard CLI a managed hook launches, attested from the caller's facts:
//! `resolve_attested_guard_cli`, `GuardCliAttestation.manifest_payload` and
//! `executable_identity_payload` (`guard/adapters/guard_cli_attestation.py`
//! and `hook_python.py` before they moved here).
//!
//! A frozen Guard is its own launcher, so only the launcher's executable
//! identity is read. Any other Guard runs on the interpreter that asked: the
//! `hook_python_identity` kind runs it isolated, from the package and
//! distribution facts its caller stamp carries (`attest_facts`), and accepts
//! the import record only when it matches.

use serde_json::{json, Map, Value};

use super::{caller, Ctx, Step};
use crate::pyjson::PyVal;

/// The console entry point a non-frozen Guard CLI must expose.
const ENTRY_POINT: &str = "codex_plugin_scanner.cli:main";
/// `HookPythonAttestation` fields the `attest` op answers.
const EXPECTED_PATHS: [&str; 4] = [
    "package_file",
    "package_root",
    "cryptography_file",
    "cryptography_distribution_root",
];
const UNAVAILABLE: &str = "guard_hook_python_interpreter_unavailable";
/// The error a non-frozen Guard reports for any attestation failure.
pub(super) const REINSTALL: &str = "Guard could not attest its CLI runtime. Reinstall hol-guard \
     with pipx or uv, then re-run the harness installation.";
/// The only caller environment the isolated probe inherits.
const INHERITED: [&str; 7] = [
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LANG",
    "LC_ALL",
];
const STAT_KEYS: [&str; 5] = ["device", "inode", "mode", "size", "mtime_ns"];
const TEXT_KEYS: [&str; 4] = [
    "invocation_path",
    "invocation_type",
    "target_path",
    "target_sha256",
];

/// The interpreter a non-frozen Guard CLI runs on.
pub(super) struct HookPython {
    pub(super) executable: String,
    pub(super) target: String,
    pub(super) import_roots: Vec<String>,
}

/// One attested Guard CLI.
pub(super) struct Attested {
    /// The argv prefix that runs the CLI.
    pub(super) command: Vec<String>,
    /// `manifest_payload()`, in the order Python wrote it.
    pub(super) identity: PyVal,
    /// `executable_identity_payload` of the attested executable.
    pub(super) interpreter: PyVal,
    /// `None` for a frozen Guard.
    pub(super) python: Option<HookPython>,
}

impl Attested {
    /// `guard_hook_command(...)[:-3]`: the argv before `--harness`.
    pub(super) fn hook_prefix(&self) -> Vec<String> {
        let mut prefix = self.command.clone();
        if self.python.is_some() {
            prefix.push("guard".into());
        }
        prefix.push("hook".into());
        prefix
    }
}

fn str_val(text: &str) -> PyVal {
    PyVal::Str(text.to_owned())
}

fn is_integer(digits: &str) -> bool {
    let digits = digits.strip_prefix('-').unwrap_or(digits);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn stat(value: Option<&Value>) -> Result<PyVal, &'static str> {
    let fields = value
        .and_then(Value::as_object)
        .filter(|fields| fields.len() == STAT_KEYS.len())
        .ok_or(UNAVAILABLE)?;
    STAT_KEYS
        .iter()
        .map(|key| match fields.get(*key) {
            Some(Value::Number(number)) if is_integer(&number.to_string()) => {
                Ok(((*key).to_owned(), PyVal::Int(number.to_string())))
            }
            _ => Err(UNAVAILABLE),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(PyVal::Dict)
}

/// `_native_identity` then `executable_identity_payload`: the identity the
/// kind answered for `invocation`, checked and in Python's field order.
fn identity_payload(identity: Option<&Value>, invocation: &str) -> Result<PyVal, &'static str> {
    let fields = identity
        .and_then(Value::as_object)
        .filter(|fields| fields.len() == TEXT_KEYS.len() + 3)
        .ok_or(UNAVAILABLE)?;
    let text = |key: &str| fields.get(key).and_then(Value::as_str).ok_or(UNAVAILABLE);
    for key in TEXT_KEYS {
        text(key)?;
    }
    let link = match fields.get("invocation_link_target") {
        Some(Value::Null) => PyVal::Null,
        Some(Value::String(link)) => str_val(link),
        _ => return Err(UNAVAILABLE),
    };
    if text("invocation_path")? != invocation
        || !matches!(text("invocation_type")?, "file" | "symlink")
    {
        return Err(UNAVAILABLE);
    }
    Ok(PyVal::Dict(vec![
        ("invocation_path".into(), str_val(invocation)),
        ("invocation_type".into(), str_val(text("invocation_type")?)),
        ("invocation_link_target".into(), link),
        (
            "invocation_stat".into(),
            stat(fields.get("invocation_stat"))?,
        ),
        ("target_path".into(), str_val(text("target_path")?)),
        ("target_stat".into(), stat(fields.get("target_stat"))?),
        ("target_sha256".into(), str_val(text("target_sha256")?)),
    ]))
}

/// One `hook_python_identity` answer: its fields, or the error it named.
fn identity_kind(request: &Value, keys: &[&str]) -> Result<Map<String, Value>, String> {
    let answer = crate::hook_python_identity::dispatch(request).map_err(|_| UNAVAILABLE)?;
    let Value::Object(answer) = answer else {
        return Err(UNAVAILABLE.into());
    };
    if let (1, Some(Value::String(error))) = (answer.len(), answer.get("error")) {
        return Err(error.clone());
    }
    if answer.len() != keys.len() || keys.iter().any(|key| !answer.contains_key(*key)) {
        return Err(UNAVAILABLE.into());
    }
    Ok(answer)
}

/// `_frozen_guard_cli_attestation`: the frozen launcher's own identity.
fn frozen(ctx: &Ctx) -> Step<Result<Attested, String>> {
    let launcher = ctx.absolute(std::path::Path::new(caller::frozen_launcher(ctx)?));
    let invocation = super::path_text(&launcher);
    let identity = identity_kind(
        &json!({"op": "executable", "path": invocation}),
        &["identity"],
    )
    .and_then(|answer| Ok(identity_payload(answer.get("identity"), &invocation)?));
    let identity = match identity {
        Ok(identity) => identity,
        Err(error) => return Ok(Err(error)),
    };
    let command = vec![invocation];
    let manifest = PyVal::Dict(vec![
        ("schema".into(), PyVal::Int("1".into())),
        ("runtime".into(), str_val("frozen-core")),
        (
            "command".into(),
            PyVal::List(command.iter().map(|part| str_val(part)).collect()),
        ),
        ("entry_point".into(), str_val("hol-guard")),
        ("guard_version".into(), str_val(caller::version(ctx)?)),
        ("package_file".into(), PyVal::Null),
        ("package_root".into(), PyVal::Null),
        ("hol_distribution_root".into(), PyVal::Null),
        ("interpreter".into(), identity.clone()),
    ]);
    Ok(Ok(Attested {
        command,
        identity: manifest,
        interpreter: identity,
        python: None,
    }))
}

/// Where the probe runs: a private directory owned by this request when
/// `scoped` (`disposable_guard_hook_probe`), else `runtime/python-probe`
/// under the Guard home.
fn probe(ctx: &Ctx, scoped: Option<&tempfile::TempDir>) -> Result<Value, String> {
    match scoped {
        Some(directory) => {
            let path = std::fs::canonicalize(directory.path())
                .map_err(|_| "guard_hook_python_neutral_cwd_unavailable")?;
            Ok(json!({"scoped": super::path_text(&path)}))
        }
        None => Ok(json!({"guard_home": super::path_text(&ctx.absolute(&ctx.guard_home))})),
    }
}

/// `attest_guard_hook_python`: the running interpreter, attested.
fn python(ctx: &Ctx, scoped: Option<&tempfile::TempDir>) -> Step<Result<Attested, String>> {
    let executable = caller::executable(ctx)?.to_owned();
    let version = caller::version(ctx)?.to_owned();
    let facts = match ctx.caller.get("attest_facts") {
        Some(Value::Object(facts)) => match facts.get("error") {
            Some(Value::String(_)) => return Ok(Err(REINSTALL.into())),
            _ => Value::Object(facts.clone()),
        },
        _ => return Ok(Err(REINSTALL.into())),
    };
    let inherited: Map<String, Value> = INHERITED
        .iter()
        .filter_map(|key| Some(((*key).to_owned(), json!(ctx.env(key)?))))
        .collect();
    let answer = probe(ctx, scoped).and_then(|probe| {
        identity_kind(
            &json!({
                "op": "attest",
                "python": executable,
                "inherited": inherited,
                "probe": probe,
                "facts": facts,
            }),
            &["identity", "expected"],
        )
    });
    let attested = answer.ok().and_then(|answer| {
        let identity = identity_payload(answer.get("identity"), &executable).ok()?;
        let expected = answer.get("expected")?.as_object()?;
        let path = |key: &str| expected.get(key)?.as_str();
        let roots: Vec<String> = expected
            .get("import_roots")?
            .as_array()?
            .iter()
            .map(|root| root.as_str().map(str::to_owned))
            .collect::<Option<_>>()?;
        let hol_root = match expected.get("hol_distribution_root")? {
            Value::Null => PyVal::Null,
            Value::String(root) => str_val(root),
            _ => return None,
        };
        let shaped = expected.len() == EXPECTED_PATHS.len() + 4
            && EXPECTED_PATHS.iter().all(|key| path(key).is_some())
            && path("version") == Some(version.as_str())
            && path("entry_point") == Some(ENTRY_POINT);
        if !shaped {
            return None;
        }
        let target = identity.get("target_path")?.as_str()?.to_owned();
        let command = vec![
            executable.clone(),
            "-I".into(),
            "-s".into(),
            "-m".into(),
            "codex_plugin_scanner.cli".into(),
        ];
        let manifest = PyVal::Dict(vec![
            ("schema".into(), PyVal::Int("1".into())),
            (
                "command".into(),
                PyVal::List(command.iter().map(|part| str_val(part)).collect()),
            ),
            ("entry_point".into(), str_val(ENTRY_POINT)),
            ("guard_version".into(), str_val(&version)),
            ("package_file".into(), str_val(path("package_file")?)),
            ("package_root".into(), str_val(path("package_root")?)),
            ("hol_distribution_root".into(), hol_root),
            ("interpreter".into(), identity.clone()),
        ]);
        Some(Attested {
            command,
            identity: manifest,
            interpreter: identity,
            python: Some(HookPython {
                executable: executable.clone(),
                target,
                import_roots: roots,
            }),
        })
    });
    Ok(attested.ok_or_else(|| REINSTALL.to_owned()))
}

/// `tempfile.TemporaryDirectory(prefix="hol-guard-hook-probe-")`: private
/// (0700) like Python's, since the probe refuses a directory anyone else can
/// enter.
fn scoped_probe_dir(ctx: &Ctx) -> std::io::Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("hol-guard-hook-probe-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir_in(caller_temp_dir(ctx))
}

/// `tempfile.gettempdir()` as the caller would answer it: its `TMPDIR`,
/// `TEMP` or `TMP` when that names a directory, else this process's own. The
/// resident's temp directory can be one the caller no longer has.
fn caller_temp_dir(ctx: &Ctx) -> std::path::PathBuf {
    ["TMPDIR", "TEMP", "TMP"]
        .iter()
        .filter_map(|key| ctx.env(key).filter(|value| !value.is_empty()))
        .map(|value| ctx.absolute(std::path::Path::new(value)))
        .find(|path| path.is_dir())
        .unwrap_or_else(std::env::temp_dir)
}

/// `resolve_attested_guard_cli`: the attested CLI, or the error a harness
/// reports. `scoped` runs a non-frozen probe in a directory this request
/// owns and removes, as an install preparation does.
pub(super) fn attested(ctx: &Ctx, scoped: bool) -> Step<Result<Attested, String>> {
    if caller::frozen(ctx)? {
        return frozen(ctx);
    }
    if !scoped {
        return python(ctx, None);
    }
    let directory = scoped_probe_dir(ctx);
    match directory {
        Ok(directory) => python(ctx, Some(&directory)),
        Err(_) => Ok(Err(REINSTALL.into())),
    }
}

#[cfg(test)]
#[path = "attested_cli_tests.rs"]
mod tests;
