//! Wire validation is distinct from the native MAC-backed store check.

use guard_contracts::{
    NativeBashHostV1, NativeBashReviewDescriptorV1, NATIVE_BASH_ARTIFACT_ID,
    NATIVE_BASH_REVIEW_ARTIFACT_TYPE, NATIVE_BASH_REVIEW_DESCRIPTOR_SCHEMA,
};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) fn reserved(kind: Option<&str>, id: Option<&str>, descriptor: Option<&Value>) -> bool {
    kind == Some(NATIVE_BASH_REVIEW_ARTIFACT_TYPE)
        || descriptor.is_some()
        || matches!(
            id,
            Some(
                NATIVE_BASH_ARTIFACT_ID
                    | "native-bash-launch:v1"
                    | "native-bash-owner:native-pretool:v1"
                    | "native-bash-owner:native-pretool:v2"
            )
        )
}

pub(crate) fn validate(
    descriptor: &NativeBashReviewDescriptorV1,
    harness: &str,
    command: &str,
) -> Result<(), &'static str> {
    let subject = &descriptor.subject;
    let lineage = &descriptor.review_lineage;
    if descriptor.schema != NATIVE_BASH_REVIEW_DESCRIPTOR_SCHEMA
        || descriptor.artifact_id != NATIVE_BASH_ARTIFACT_ID
        || lineage.schema != "guard-native-bash-review-lineage.v1"
        || lineage.artifact_hash != descriptor.artifact_hash
        || !guard_contracts::native_bash_operation_id_is_valid(&lineage.operation_id)
        || lineage.lineage_id.len() != 64
        || !lineage
            .lineage_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || lineage.created_at_ms.checked_add(86_400_000) != Some(lineage.expires_at_ms)
        || !matches!(
            (harness, subject.context.host),
            ("omp", NativeBashHostV1::OmpInputRewriteV1)
                | ("pi", NativeBashHostV1::PiInputMutationV1)
        )
    {
        return Err("native_bash_review_descriptor_invalid");
    }
    subject.validate()?;
    if command.trim().is_empty() || command.len() > 65_536 {
        return Err("native_bash_review_command_mismatch");
    }
    let model = guard_command::command_model::parse_shell_command(
        command,
        Some(Path::new(&subject.context.cwd)),
        Some(Path::new(&subject.context.home)),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    if !crate::native_exact_action_op::is_safe_single_invocation(&model)
        || model.segments[0].arguments != subject.argv
        || model.segments[0]
            .executable
            .as_deref()
            .and_then(|path| Path::new(path).file_name())
            .is_none_or(|name| name != "bash")
    {
        return Err("native_bash_review_command_mismatch");
    }
    let bindings = [
        (
            "identity",
            serde_json::to_value(&subject.context)
                .map_err(|_| "native_bash_review_descriptor_invalid")?,
        ),
        (
            "content",
            json!({"subject_sha256":subject.identity_sha256()?}),
        ),
        (
            "capabilities",
            json!({"profile":NATIVE_BASH_ARTIFACT_ID,"argv":subject.argv,"outputs":subject.outputs}),
        ),
        ("sandbox", json!({"assurance":subject.execution_assurance})),
    ];
    if bindings.iter().any(|(key, value)| {
        !crate::context_digest::component_matches(&descriptor.artifact_hash, key, value)
    }) {
        return Err("native_bash_review_context_mismatch");
    }
    Ok(())
}

pub(crate) fn eligible(
    kind: Option<&str>,
    id: Option<&str>,
    hash: Option<&str>,
    harness: Option<&str>,
    command: Option<&str>,
    project: Option<&str>,
    descriptor: Option<&Value>,
) -> bool {
    if kind != Some(NATIVE_BASH_REVIEW_ARTIFACT_TYPE) || id != Some(NATIVE_BASH_ARTIFACT_ID) {
        return false;
    }
    let (Some(value), Some(harness), Some(command)) = (descriptor, harness, command) else {
        return false;
    };
    let Ok(descriptor) = serde_json::from_value::<NativeBashReviewDescriptorV1>(value.clone())
    else {
        return false;
    };
    let Some(now) = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
    else {
        return false;
    };
    hash == Some(descriptor.artifact_hash.as_str())
        && project == Some(descriptor.subject.context.project.as_str())
        && descriptor.review_lineage.created_at_ms <= now
        && now <= descriptor.review_lineage.expires_at_ms
        && validate(&descriptor, harness, command).is_ok()
}
