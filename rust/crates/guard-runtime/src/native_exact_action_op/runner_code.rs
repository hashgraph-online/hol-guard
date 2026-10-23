//! Loaded-code identity for persistent runner consent, not CLI identification.
//! Metadata selection alone never proves the code a manager or bin can load.
use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;
use super::reasons::{Proof, SENSITIVE_PATH, UNPROVEN_LAUNCH};

const UNPROVEN: &str = "runner_code_closure_unproven";
const MAX_SOURCE: u64 = 2 * 1024 * 1024;

pub(super) fn version_identity(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let stat = map.get("path").is_some_and(Value::is_string)
                && map.get("device").is_some_and(Value::is_u64)
                && map.get("inode").is_some_and(Value::is_u64);
            Value::Object(
                map.into_iter()
                    .filter_map(|(key, value)| {
                        if stat
                            && matches!(
                                key.as_str(),
                                "device" | "inode" | "modified_time_ns" | "change_time_ns" | "size"
                            )
                        {
                            None
                        } else {
                            Some((key, version_identity(value)))
                        }
                    })
                    .collect(),
            )
        }
        Value::Array(values) => Value::Array(values.into_iter().map(version_identity).collect()),
        other => other,
    }
}

fn closure_error(reason: &'static str) -> &'static str {
    if reason == SENSITIVE_PATH || reason == UNPROVEN_LAUNCH || reason.starts_with("node_") {
        reason
    } else {
        UNPROVEN
    }
}

fn script(path: &str, expected: &str, args: &[String], cwd: &str, ctx: &Ctx) -> Proof<Value> {
    ctx.check()?;
    let resolved = fs_path::resolve_strict(path).ok_or(UNPROVEN)?;
    if guard_command::secret_path_probe::is_request_secret_path(
        &resolved,
        Some(std::path::Path::new(cwd)),
        ctx.home.map(std::path::Path::new),
    ) {
        return Err(SENSITIVE_PATH);
    }
    let bytes = fs_path::read_bounded(&resolved, MAX_SOURCE).ok_or(UNPROVEN)?;
    let digest = fs_path::sha256_hex(&bytes);
    if expected.strip_prefix("sha256:").unwrap_or(expected) != digest {
        return Err(UNPROVEN);
    }
    let source = std::str::from_utf8(&bytes).map_err(|_| UNPROVEN)?;
    let launch = ctx
        .engines
        .launch_identity(&resolved, args, cwd, ctx.home, ctx.env);
    if !ctx.engines.launch_reusable(&launch) {
        return Err(UNPROVEN);
    }
    let argv = guard_command::launch_identity::resolved_runtime_launch_argv(&launch, args)
        .ok_or(UNPROVEN)?;
    let (program, arguments) = argv.split_first().ok_or(UNPROVEN)?;
    // An opaque compiled manager/bin is not a source-closure proof. Resolve
    // the actual verified shebang argv, including loader flags, not its name.
    if launch["entrypoint"]["status"] != "verified" {
        return Err(UNPROVEN);
    }
    let interpreter = ctx
        .engines
        .launch_identity(program, arguments, cwd, ctx.home, ctx.env);
    if !ctx.engines.launch_reusable(&interpreter)
        || interpreter["executable"]["file_format"] != "native"
    {
        return Err(UNPROVEN);
    }
    let name = fs_path::name(program).to_lowercase();
    let code = if super::node_script::NODE_LAUNCHERS.contains(&name.as_str()) {
        super::node_script::node_script(arguments, cwd, ctx).map_err(closure_error)?
    } else if super::launcher_sets::is_python_launcher(&name) {
        super::python_script::observe(arguments, cwd, ctx, &interpreter["executable"])
            .map_err(closure_error)?
    } else if matches!(name.as_str(), "sh" | "bash" | "dash" | "ash")
        && arguments.first() == Some(&resolved)
        && source
            .lines()
            .all(|line| line.trim().is_empty() || line.trim_start().starts_with('#'))
        && !ctx.env.iter().any(|(name, value)| {
            !value.is_empty()
                && (matches!(name.as_str(), "BASH_ENV" | "ENV" | "SHELLOPTS")
                    || name.starts_with("BASH_FUNC_"))
        })
    {
        // The launcher path is canonical, so a distribution whose /bin/sh is a
        // link to another POSIX shell names that shell here. Only shells whose
        // noninteractive script startup reads nothing beyond the guarded
        // variables above belong in this set: zsh and ksh always source a
        // startup file, so a comment-only program under them is not empty.
        // Only a truly empty noninteractive shell program is closed here.
        // Shell commands need the existing Bash graph/owning route; a hash
        // or an arbitrary launcher basename cannot substitute for it.
        json!({"script":resolved,"kind":"empty-shell","sha256":digest})
    } else {
        return Err(UNPROVEN);
    };
    if code["script"].as_str() != Some(resolved.as_str()) {
        return Err(UNPROVEN);
    }
    let root_digest = code.get("sha256").and_then(Value::as_str).or_else(|| {
        code.get("modules")?.as_array()?.iter().find_map(|entry| {
            (entry["path"].as_str() == Some(resolved.as_str()))
                .then(|| entry["sha256"].as_str())
                .flatten()
        })
    });
    if root_digest != Some(digest.as_str()) {
        return Err(UNPROVEN);
    }
    // Refuse an entry that changed between package-intent, launch and graph
    // reads. This is identity validation, not an execution-race guarantee.
    if launch["executable"]["sha256"].as_str() != Some(digest.as_str()) {
        return Err(UNPROVEN);
    }
    ctx.check()?;
    // Stat observations validate each fresh read above. They are not code
    // versions and never replace current validation or execution assurance.
    Ok(
        json!({"launch":version_identity(launch),"interpreter":version_identity(interpreter),"code":code}),
    )
}

pub(super) fn bind(
    record: &Value,
    runner: &str,
    args: &[String],
    cwd: &str,
    ctx: &Ctx,
) -> Proof<Value> {
    let field = |value: &Value, name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or(UNPROVEN)
    };
    let manager = record.get("manager").ok_or(UNPROVEN)?;
    let manager_code = script(
        &field(manager, "resolved_path")?,
        &field(manager, "content_hash")?,
        args,
        cwd,
        ctx,
    )?;
    let (_, bin_args) = super::runner_bin::runner_split(runner, args).ok_or(UNPROVEN)?;
    let bin_code = script(
        &field(record, "resolved_path")?,
        &field(record, "content_hash")?,
        bin_args,
        cwd,
        ctx,
    )?;
    let target = record
        .get("bin_target")
        .map(|target| {
            script(
                &field(target, "resolved_path")?,
                &field(target, "content_hash")?,
                bin_args,
                cwd,
                ctx,
            )
        })
        .transpose()?;
    Ok(json!({"manager":manager_code,"bin":bin_code,"shim_target":target}))
}
