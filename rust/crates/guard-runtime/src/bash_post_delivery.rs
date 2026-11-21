//! A host observation is not authority. Only the resident's signed operation
//! and invocation records can identify a native owner's result/control reply.

#[cfg(target_os = "macos")]
use crate::policy_store::policy_store_approval::bash_journal::BashOperationJournal;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::NativeHookRequestV1;
#[cfg(target_os = "macos")]
use serde::Deserialize;
#[cfg(target_os = "macos")]
use std::path::Path;

pub(crate) struct VerifiedBashDelivery {
    clean_completion: bool,
}

impl VerifiedBashDelivery {
    pub(crate) fn clean_completion(&self) -> bool {
        self.clean_completion
    }
}

#[cfg(target_os = "macos")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema: String,
    operation_id: String,
    tool_call_id: String,
    exit_code: i32,
}

/// No writes, acknowledgement, consent claim, or execution occur here.
#[cfg(target_os = "macos")]
pub(crate) fn verify(
    request: &NativeHookRequestV1,
    store: &PolicySnapshotStore,
) -> Option<VerifiedBashDelivery> {
    if request.event_name != "PostToolUse"
        || !matches!(request.harness.as_str(), "omp" | "pi")
        || request.payload.get("tool_name")?.as_str()? != "bash"
    {
        return None;
    }
    let observation: Observation =
        serde_json::from_value(request.payload.get("guard_bash_owner_delivery")?.clone()).ok()?;
    if observation.schema != "guard-native-bash-post-observation.v1"
        || !(0..=255).contains(&observation.exit_code)
        || request.payload.get("tool_call_id")?.as_str()? != observation.tool_call_id
        || !observation
            .operation_id
            .strip_prefix("bash-operation:")
            .is_some_and(|id| id.len() == 64 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return None;
    }
    let command = request.payload.pointer("/tool_input/command")?.as_str()?;
    if command.len() > 32_768 {
        return None;
    }
    let args = crate::mcp_proxy_shlex::split(command)?;
    // Exact single-quoted rendering rules out substitutions, redirects and
    // compound siblings that a shell-word parser alone cannot disprove.
    let canonical = args
        .iter()
        .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ");
    if command != canonical || !matches!(args.len(), 20 | 22) {
        return None;
    }
    for (index, flag) in [
        (1, "execute-bound-bash"),
        (2, "--harness"),
        (4, "--operation-id"),
        (6, "--host-owner-pid"),
        (8, "--tool-call-id"),
        (10, "--guard-home"),
        (12, "--workspace"),
        (14, "--request-file"),
        (16, "--request-sha256"),
        (18, "--timeout-seconds"),
    ] {
        if args[index] != flag {
            return None;
        }
    }
    let file = Path::new(&args[15]);
    let digest = &args[17];
    if !Path::new(&args[0]).is_absolute()
        || args[3] != request.harness
        || args[5] != observation.operation_id
        || args[9] != observation.tool_call_id
        || args[11] != request.guard_home
        || args[7].parse::<i32>().ok().is_none_or(|pid| pid <= 1)
        || !args[19]
            .parse::<u32>()
            .ok()
            .is_some_and(|seconds| (1..=120).contains(&seconds))
        || !file.is_absolute()
        || file.file_name()?.to_str()? != "request.json"
        || !file
            .parent()?
            .file_name()?
            .to_str()?
            .starts_with("hol-guard-contained-test-")
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || args.len() == 22 && (args[20] != "--home" || args[21] != request.home_dir)
        || Path::new(&args[13]).canonicalize().ok()?
            != Path::new(request.cwd.as_deref()?).canonicalize().ok()?
    {
        return None;
    }
    // OMP may report the physical cwd through macOS's /tmp alias. Match the
    // same canonical project used by the authenticated invocation allocation.
    let project = Path::new(&args[13]).canonicalize().ok()?;
    store.require_guard_home(&request.guard_home).ok()?;
    let store_path = Path::new(&request.guard_home).join("guard.db");
    let journal = BashOperationJournal::open_for_delivery(
        store,
        store_path.to_str()?,
        &observation.operation_id,
    )
    .ok()?;
    let clean_completion = journal
        .confirm_delivery_call(
            &request.harness,
            project.to_str()?,
            &observation.tool_call_id,
            observation.exit_code,
        )
        .ok()??;
    Some(VerifiedBashDelivery { clean_completion })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn verify(
    _request: &NativeHookRequestV1,
    _store: &PolicySnapshotStore,
) -> Option<VerifiedBashDelivery> {
    None
}
