//! Read-only launch identity checks shared with the native bridge.
use super::*;

/// Reuse the manifest verifier's executable and file identity checks after
/// the bridge has authenticated the enclosing manifest. No child is spawned.
pub(crate) fn authenticated_launch_files(
    interpreter: &Value,
    files: &[Value],
    deadline: std::time::Instant,
) -> bool {
    let mut request: CodexHookManifestVerifyRequestV1 = match serde_json::from_value(json!({
        "schema": CODEX_HOOK_MANIFEST_VERIFY_REQUEST_SCHEMA, "posix": cfg!(unix),
    })) {
        Ok(value) => value,
        Err(_) => return false,
    };
    #[cfg(unix)]
    {
        request.current_uid = Some(nix::unistd::getuid().as_raw());
    }
    for path in files
        .iter()
        .filter_map(|item| item.get("path").and_then(Value::as_str))
        .chain(interpreter.get("invocation_path").and_then(Value::as_str))
        .chain(interpreter.pointer("/target/path").and_then(Value::as_str))
    {
        let Some(canonical) = crate::codex_hook_bridge::registration::canonical(Path::new(path))
        else {
            return false;
        };
        request.canonical_paths.insert(path.to_owned(), canonical);
    }
    let mut verifier = Verifier {
        request: &request,
        matches: [false; 4],
        questions: Vec::new(),
    };
    if verifier.executable(interpreter).is_err() {
        return false;
    }
    let mut roles = std::collections::BTreeSet::new();
    for file in files {
        if std::time::Instant::now() >= deadline || verifier.regular_identity(file).is_err() {
            return false;
        }
        let Some(role) = file.get("role").and_then(Value::as_str) else {
            return false;
        };
        if !roles.insert(role) {
            return false;
        }
    }
    let required = [
        "bridge",
        "bridge_runtime",
        "daemon_entrypoint",
        "daemon_manager",
        "fallback_entrypoint",
        "launch_runtime",
        "runtime_trust",
        "windows_job",
    ];
    required.iter().all(|role| roles.contains(role))
        && roles
            .iter()
            .all(|role| required.contains(role) || ["hook_probe", "native_receipt"].contains(role))
        && (roles.contains("hook_probe") == roles.contains("native_receipt"))
        && verifier.questions.is_empty()
}
