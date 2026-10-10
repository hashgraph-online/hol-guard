//! Canonical request context: admission plus one-round-trip construction.
//!
//! Admission checks the caller-declared owner, remaining budget and policy
//! generation, then builds the shell working-directory model and the runtime
//! launch identity from the real filesystem. The reply carries a canonical
//! digest over everything that was derived; nothing the caller computed is
//! trusted as authority.

use std::path::Path;
use std::time::{Duration, Instant};

use guard_contracts::{
    RequestContextBuildV1, RequestContextExecutableV1, RequestContextKindV1,
    RequestContextRequestV1, RequestContextResultV1, MAX_REQUEST_CONTEXT_ARGV,
    MAX_REQUEST_CONTEXT_BUDGET_MS, MAX_REQUEST_CONTEXT_PATH_BYTES,
    MAX_REQUEST_CONTEXT_SCRIPT_BYTES, REQUEST_CONTEXT_REQUEST_SCHEMA,
    REQUEST_CONTEXT_RESULT_SCHEMA, REQUEST_CONTEXT_SCHEMA,
};
use serde_json::{json, Value};

use crate::request_context_shell as shell;

pub(crate) const BUDGET_EXCEEDED: &str = "native_request_context_budget_exceeded";

/// Remaining-budget clock started when the resident admits the request.
pub(crate) struct Budget {
    started: Instant,
    limit: Duration,
}

impl Budget {
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if self.started.elapsed() >= self.limit {
            return Err(BUDGET_EXCEEDED);
        }
        Ok(())
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.started + self.limit
    }

    fn remaining_ms(&self) -> u64 {
        self.limit
            .saturating_sub(self.started.elapsed())
            .as_millis() as u64
    }
}

pub(crate) fn evaluate_request_context_request(
    request: &RequestContextRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != REQUEST_CONTEXT_REQUEST_SCHEMA {
        return Err("native_request_context_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match decide(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::resident_protocol::encode_response(&RequestContextResultV1 {
        schema: REQUEST_CONTEXT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

pub(crate) fn request_digest(request: &RequestContextRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_request_context_request_invalid".to_owned())?;
    canonical_digest(&material).map_err(str::to_owned)
}

fn canonical_digest(value: &Value) -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(value, &mut bytes, usize::MAX)
        .map_err(|_| "native_request_context_request_invalid")?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

fn path_is_admissible(text: &str) -> bool {
    !text.contains('\0') && text.len() <= MAX_REQUEST_CONTEXT_PATH_BYTES
}

fn admit(request: &RequestContextRequestV1) -> Result<Budget, &'static str> {
    if request.request_id.is_empty() || request.request_id.len() > 256 {
        return Err("native_request_context_request_id_invalid");
    }
    if request.guard_home.is_empty()
        || !path_is_admissible(&request.guard_home)
        || !Path::new(&request.guard_home).is_absolute()
    {
        return Err("native_request_context_guard_home_invalid");
    }
    if request.budget_ms == 0 || request.budget_ms > MAX_REQUEST_CONTEXT_BUDGET_MS {
        return Err("native_request_context_budget_invalid");
    }
    admit_owner(request.owner_uid)?;
    Ok(Budget {
        started: Instant::now(),
        limit: Duration::from_millis(request.budget_ms),
    })
}

#[cfg(unix)]
fn admit_owner(owner_uid: Option<u32>) -> Result<(), &'static str> {
    match owner_uid {
        Some(uid) if uid == nix::unistd::geteuid().as_raw() => Ok(()),
        _ => Err("native_request_context_owner_mismatch"),
    }
}

#[cfg(not(unix))]
fn admit_owner(owner_uid: Option<u32>) -> Result<(), &'static str> {
    match owner_uid {
        None => Ok(()),
        Some(_) => Err("native_request_context_owner_mismatch"),
    }
}

/// The resident keeps no policy state of its own (the hook admission works
/// the same way): it proves the caller's snapshot agrees with the generation
/// it claims, and binds that evaluated snapshot into the context digest.
/// Comparing against the active policy happens where the policy is evaluated.
fn admit_policy(build: &RequestContextBuildV1) -> Result<Value, &'static str> {
    let Some(policy) = &build.policy else {
        return Ok(Value::Null);
    };
    if policy.generation == 0 {
        return Err("native_request_context_policy_generation_invalid");
    }
    if !crate::edge::policy_generation_matches(&policy.snapshot, policy.generation) {
        return Err("native_request_context_policy_generation_mismatch");
    }
    Ok(crate::edge::stable_policy_identity(
        &policy.snapshot,
        policy.generation,
    ))
}

fn admit_build(build: &RequestContextBuildV1) -> Result<(), &'static str> {
    let paths = [
        build.workspace.as_deref(),
        build.cwd.as_deref(),
        build.fallback_cwd.as_deref(),
        build.home_dir.as_deref(),
    ];
    if paths.iter().flatten().any(|path| !path_is_admissible(path)) {
        return Err("native_request_context_path_invalid");
    }
    // The resident's own working directory is unrelated to the caller's: a
    // relative path would be modeled and identity-bound against the wrong
    // directory. Callers send absolute paths.
    if paths
        .iter()
        .flatten()
        .any(|path| !Path::new(path).is_absolute())
    {
        return Err("native_request_context_path_not_absolute");
    }
    if build.script.as_ref().map(String::len).unwrap_or(0) > MAX_REQUEST_CONTEXT_SCRIPT_BYTES {
        return Err("native_request_context_script_too_large");
    }
    if let Some(executable) = &build.executable {
        if executable.args.len() > MAX_REQUEST_CONTEXT_ARGV {
            return Err("native_request_context_argv_too_large");
        }
    }
    Ok(())
}

fn launch_identity(
    executable: &RequestContextExecutableV1,
    cwd: Option<&str>,
    home_dir: Option<&str>,
) -> Value {
    let launch_env = executable.launch_env.as_ref().map(|env| {
        Value::Object(
            env.iter()
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect(),
        )
    });
    guard_command::launch_identity::build_runtime_launch_identity(
        executable.command.as_ref().unwrap_or(&Value::Null),
        &executable.args,
        executable.structured_command,
        executable.direct_executable,
        executable.search_path.as_deref(),
        cwd.map(Path::new),
        home_dir.map(Path::new),
        launch_env.as_ref(),
    )
}

fn build(
    request: &RequestContextRequestV1,
    body: &RequestContextBuildV1,
    budget: &Budget,
) -> Result<Value, &'static str> {
    admit_build(body)?;
    let policy = admit_policy(body)?;
    budget.check()?;
    let shell_report = match &body.script {
        None => Value::Null,
        Some(script) => {
            let context = shell::build_shell_context(
                script,
                body.cwd.as_deref(),
                body.fallback_cwd.as_deref(),
                body.workspace.as_deref(),
                body.home_dir.as_deref(),
                budget,
            )?;
            shell::context_report(&context, budget)?
        }
    };
    budget.check()?;
    let launch_cwd = body.cwd.as_deref().or(body.fallback_cwd.as_deref());
    let launch = match &body.executable {
        None => Value::Null,
        Some(executable) => launch_identity(executable, launch_cwd, body.home_dir.as_deref()),
    };
    budget.check()?;
    let admission = json!({
        "source": request.source.as_str(),
        "owner_uid": request.owner_uid,
        "budget_ms": request.budget_ms,
        "budget_remaining_ms": budget.remaining_ms(),
        "policy": policy,
    });
    let binding = json!({
        "schema": REQUEST_CONTEXT_SCHEMA,
        "source": request.source.as_str(),
        "owner_uid": request.owner_uid,
        "policy": admission["policy"],
        "target": body.target,
        "shell_context_hash": shell_report.get("context_hash"),
        "launch": launch,
    });
    let context_sha256 = canonical_digest(&binding)?;
    Ok(json!({
        "schema": REQUEST_CONTEXT_SCHEMA,
        "admission": admission,
        "shell": shell_report,
        "launch": launch,
        "target": body.target,
        "context_sha256": context_sha256,
    }))
}

fn decide(request: &RequestContextRequestV1) -> Result<Value, &'static str> {
    let budget = admit(request)?;
    let payload = match &request.action {
        RequestContextKindV1::Build(body) => build(request, body, &budget)?,
        RequestContextKindV1::ValidateSegment {
            context,
            segment_index,
        } => shell::validate_segment(context, *segment_index, &budget)?,
        RequestContextKindV1::Hash {
            context,
            segment_index,
        } => shell::hash_context(context, *segment_index, &budget)?,
    };
    budget.check()?;
    Ok(payload)
}

#[cfg(test)]
#[path = "request_context_op_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "request_context_op_bounds_tests.rs"]
mod bounds_tests;
