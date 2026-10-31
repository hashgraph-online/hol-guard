//! The checks `_verify_hook_manifest` makes on the manifest's own fields,
//! and the reasons and messages its failures carry, kept apart from the file
//! reads in the parent op.

use std::fs;
use std::path::Path;

use guard_contracts::CodexHookManifestExpectedV1;
use serde_json::{json, Map, Value};

use crate::codex_hook_file_identity_op::{
    failed, permission_rules, verified, FileFacts, IdentityAsk,
};
use crate::codex_hook_manifest_iso_time::is_aware_iso_datetime;
use crate::guard_config_update_value::py_eq;

/// `HOOK_MANIFEST_SCHEMA_VERSION`.
pub(super) const MANIFEST_SCHEMA_VERSION: u64 = 2;
pub(super) const TRANSPORT_ROLES: [&str; 5] = [
    "bridge",
    "bridge_runtime",
    "launch_runtime",
    "runtime_trust",
    "windows_job",
];
pub(super) const REPAIR: &str = "repair the installation.";

/// One integrity failure: a stable reason and the message status shows.
pub(super) struct Failure {
    pub(super) reason: String,
    pub(super) message: String,
}

pub(super) fn fail(reason: &str, message: &str) -> Failure {
    Failure {
        reason: reason.to_owned(),
        message: message.to_owned(),
    }
}

/// A file check's failure, named and worded the way `codex_hook_file_integrity`
/// names and words it.
pub(super) fn file_failure(role: &str, kind: &str) -> Failure {
    let what = match kind {
        "missing" => "is missing",
        "not_regular" => "must be a regular file, not a symlink",
        "owner_untrusted" => "has an unexpected owner",
        "permissions_unsafe" => "is writable by another user",
        "not_executable" => "is not executable",
        "path_mismatch" => "path is no longer canonical",
        "mode_mismatch" => "permissions changed",
        "hash_mismatch" => "content changed",
        "owner_mismatch" => "owner changed",
        "invocation_mode_mismatch" => "invocation permissions changed",
        "invocation_owner_mismatch" => "invocation owner changed",
        "invocation_type_mismatch" => "invocation type changed",
        "symlink_target_mismatch" => "symlink target changed",
        "target_path_mismatch" => "target changed",
        _ => "identity is invalid",
    };
    Failure {
        reason: format!("codex_hook_{role}_{kind}"),
        message: format!("The Codex hook {role} {what}; {REPAIR}"),
    }
}

/// An identity that is not an object at all.
pub(super) fn unreadable_identity() -> Failure {
    fail(
        "codex_hook_file_identity_invalid",
        "The Codex hook manifest has an invalid packaged-file identity; repair the installation.",
    )
}

pub(super) fn field<'v>(object: &'v Map<String, Value>, key: &str) -> &'v Value {
    object.get(key).unwrap_or(&Value::Null)
}

pub(super) fn invalid_binding() -> Failure {
    fail(
        "codex_hook_manifest_registration_invalid",
        "The Codex hook manifest contains an invalid event identity; repair the installation.",
    )
}

pub(super) fn io_error() -> Failure {
    fail(
        "codex_hook_integrity_io_error",
        "Guard could not verify the Codex hook installation; run repair and inspect file permissions.",
    )
}

pub(super) fn string_list(value: &Value) -> Option<Vec<String>> {
    let Value::Array(items) = value else {
        return None;
    };
    items
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// `validate_regular_file(config_path, role="config_target")`.
pub(super) fn config_answer(ask: &IdentityAsk<'_>, path: &Path) -> Value {
    let role = "config_target";
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return failed(role, "missing", None);
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return failed(role, "not_regular", None);
    }
    match permission_rules(ask, role, &FileFacts::of(path, &metadata), false) {
        Ok(question) => verified(role, question),
        Err((kind, question)) => failed(role, kind, question),
    }
}

/// `os.access(path, os.X_OK)`, which off POSIX holds for any file that exists.
pub(super) fn invocation_executable(posix: bool, path: &Path) -> bool {
    #[cfg(unix)]
    if posix {
        return nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok();
    }
    let _ = (posix, path);
    true
}

/// `_verify_manifest_header`.
pub(super) fn header(
    manifest: &Map<String, Value>,
    expected: &CodexHookManifestExpectedV1,
) -> Result<(), Failure> {
    if !py_eq(
        field(manifest, "schema_version"),
        &json!(MANIFEST_SCHEMA_VERSION),
    ) {
        return Err(fail(
            "codex_hook_manifest_schema_unsupported",
            "The Codex hook manifest schema is stale; run `hol-guard install codex` to refresh it.",
        ));
    }
    if field(manifest, "harness").as_str() != Some("codex") {
        return Err(fail(
            "codex_hook_manifest_context_mismatch",
            "The authenticated hook manifest is not bound to the Codex harness; repair the installation.",
        ));
    }
    let config = field(manifest, "config").as_object();
    if !config.is_some_and(|config| {
        field(config, "scope").as_str() == Some("global")
            && field(config, "target").as_str() == Some(expected.config_target.as_str())
    }) {
        return Err(fail(
            "codex_hook_manifest_config_target_mismatch",
            "The Codex hook manifest is bound to another configuration target; repair the installation.",
        ));
    }
    if !py_eq(field(manifest, "context"), &expected.context) {
        return Err(fail(
            "codex_hook_manifest_context_mismatch",
            "The Codex hook manifest is bound to another Guard home or workspace; repair the installation.",
        ));
    }
    if field(manifest, "package_version").as_str() != Some(expected.package_version.as_str()) {
        return Err(fail(
            "codex_hook_manifest_package_version_stale",
            "The Codex hook manifest was generated by another Guard package version; run repair.",
        ));
    }
    if !field(manifest, "generated_at")
        .as_str()
        .is_some_and(is_aware_iso_datetime)
    {
        return Err(fail(
            "codex_hook_manifest_generated_at_invalid",
            "The Codex hook manifest generation time is invalid; repair the installation.",
        ));
    }
    Ok(())
}

/// `_verify_launch_identities`.
pub(super) fn launch_identities(
    manifest: &Map<String, Value>,
    expected: &CodexHookManifestExpectedV1,
    interpreter: &Value,
    packaged: &[(String, Map<String, Value>)],
) -> Result<(), Failure> {
    let transport_holds = field(manifest, "transport")
        .as_object()
        .is_some_and(|transport| {
            field(transport, "wrapper").is_null()
                && TRANSPORT_ROLES.iter().all(|role| {
                    let identity = packaged.iter().find(|(known, _)| known == role);
                    let identity = identity
                        .map_or(Value::Null, |(_, identity)| Value::Object(identity.clone()));
                    py_eq(field(transport, role), &identity)
                })
        });
    if !transport_holds {
        return Err(fail(
            "codex_hook_manifest_transport_invalid",
            "The Codex hook bridge identity is invalid; repair the installation.",
        ));
    }
    let launch_holds = |name: &str, argv: &[String], roles: Value| {
        field(manifest, name).as_object().is_some_and(|launch| {
            py_eq(field(launch, "argv"), &json!(argv))
                && py_eq(field(launch, "interpreter"), interpreter)
                && py_eq(field(launch, "package_roles"), &roles)
        })
    };
    if !launch_holds(
        "fallback",
        &expected.fallback_argv,
        json!(["fallback_entrypoint"]),
    ) {
        return Err(fail(
            "codex_hook_manifest_fallback_mismatch",
            "The Codex hook fallback identity changed; repair the installation.",
        ));
    }
    let daemon_roles = json!(["daemon_entrypoint", "daemon_manager"]);
    if !launch_holds("daemon_start", &expected.daemon_start_argv, daemon_roles) {
        return Err(fail(
            "codex_hook_manifest_daemon_start_mismatch",
            "The Codex daemon-start identity changed; repair the installation.",
        ));
    }
    Ok(())
}

/// `_manifest_failure_status`.
pub(super) fn failure_status(reason: &str) -> &'static str {
    match reason {
        "codex_hook_config_target_missing"
        | "codex_hook_manifest_missing"
        | "codex_hook_manifest_secret_missing"
        | "codex_hook_registration_missing" => "missing",
        "codex_hook_manifest_key_mismatch"
        | "codex_hook_manifest_installation_mismatch"
        | "codex_hook_manifest_context_mismatch"
        | "codex_hook_manifest_config_target_mismatch" => "foreign",
        "codex_hook_manifest_schema_unsupported"
        | "codex_hook_manifest_package_version_stale"
        | "codex_hook_manifest_registration_stale"
        | "codex_hook_manifest_packaged_files_stale" => "stale",
        _ => "tampered",
    }
}
