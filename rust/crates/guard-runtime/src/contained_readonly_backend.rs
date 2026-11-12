//! The argv that starts a read-only plan under this host's sandbox.
//!
//! macOS compiles the plan's Seatbelt profile and hands it to the backend.
//! Linux has no profile: the operation Guard's own sink asks builds the
//! bubblewrap namespace, pins the plan in the run's private directory and
//! starts this binary inside it to enforce that plan. A Node run there is
//! launched with Node's memory bounds (`process::NODE_MEMORY`).

use super::*;

pub(super) const BUBBLEWRAP: &str = "linux-bubblewrap";

/// Whether `plan` runs Node under Linux's sandbox, which bounds its
/// writable memory rather than its address space.
pub(super) fn node_memory(plan: &ReadonlyPlan) -> bool {
    plan.backend == BUBBLEWRAP
        && matches!(
            plan.profile_version.as_str(),
            NODE_EVAL_PROFILE
                | VITEST_PROFILE
                | NODE_TEST_PROFILE
                | NODE_TOOL_PROFILE
                | NODE_BUILD_PROFILE
        )
}

/// The argv that starts `plan` under its read-only sandbox.
pub(super) fn argv(plan: &ReadonlyPlan, private: &PrivateRoot) -> Outcome<Vec<String>> {
    let mut fields = json!({
        "profile_version": plan.profile_version,
        "workspace": plan.workspace,
        "cwd": plan.cwd,
        "allowed_executables": plan.allowed_executables,
        "read_only_roots": plan.read_only_roots,
        "output_roots": plan.output_roots,
        "command": plan.command,
        "backend_executable": plan.backend_executable,
        "private_root": path_text(&private.path)?,
    });
    if plan.backend == BUBBLEWRAP {
        fields["backend"] = json!(BUBBLEWRAP);
        fields["platform"] = json!(HOST_PLATFORM);
        let words = native("linux_readonly_argv", fields)?;
        return serde_json::from_value(words).map_err(|_| unavailable("invalid_reply"));
    }
    fields["user_site_root"] = json!(plan.user_site_root);
    let Value::String(profile) = native("macos_profile", fields)? else {
        return Err(unavailable("invalid_reply"));
    };
    let mut backend = vec![
        plan.backend_executable.clone(),
        "-p".to_owned(),
        profile,
        "--".to_owned(),
    ];
    backend.extend(plan.command.iter().cloned());
    Ok(backend)
}

#[cfg(test)]
#[path = "contained_readonly_backend_tests.rs"]
mod tests;
