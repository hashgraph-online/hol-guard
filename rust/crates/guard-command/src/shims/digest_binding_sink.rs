//! Does a verified package shim own this external-archive download?
//!
//! An external archive is approved against the digest of the bytes that are
//! actually fetched, and only the shim can bind that digest, because it
//! performs the download itself. This answers whether the command about to run
//! is a bare launch of a healthy installed shim, which is the one case where
//! the shim, rather than the hook, owns the approval.
//!
//! Every reason to say no is a reason to leave the approval with the user, so
//! an unreadable manifest, a stale shim or a command that reaches a second
//! program all answer `false`.

use serde_json::Value;

use super::status::package_shim_status;
use super::{ShimContext, ShimResult};
use crate::package_shim_invocation::command_invokes_executable;

/// `true` only when `command` is a bare launch of `executable` and that
/// executable resolves to the installed shim for `manager` with `ok` integrity.
pub fn package_shim_digest_binding_sink(
    context: &ShimContext,
    manager: &str,
    executable: &str,
    command: Option<&str>,
    path_env: Option<&str>,
) -> ShimResult<bool> {
    let facts = &context.facts;
    // The rule is written for POSIX shell words; Windows launches are left to
    // the user rather than judged by a word model that does not describe them.
    if facts.windows {
        return Ok(false);
    }
    // A bare name would be resolved through PATH at launch, which is not the
    // same thing as naming the shim.
    if !executable.contains('/') && !executable.contains('\\') {
        return Ok(false);
    }
    let Some(command) = command else {
        return Ok(false);
    };
    if !command_invokes_executable(command, executable) {
        return Ok(false);
    }
    let status = package_shim_status(context, path_env)?;
    let Some(shim_path) = healthy_shim_path(&status, manager) else {
        return Ok(false);
    };
    let Some(resolved_shim) = resolve_existing(context, &shim_path) else {
        return Ok(false);
    };
    let candidate = facts.expanduser(executable)?;
    let candidate = if facts.is_abs(&candidate) {
        candidate
    } else {
        let base = context
            .workspace_dir
            .clone()
            .unwrap_or_else(|| facts.cwd.clone());
        facts.join(&base, &candidate)
    };
    let Some(resolved_executable) = resolve_existing(context, &candidate) else {
        return Ok(false);
    };
    Ok(facts.path_eq(&resolved_executable, &resolved_shim))
}

/// The installed shim's path for `manager`, when that shim reports `ok`.
fn healthy_shim_path(status: &serde_json::Map<String, Value>, manager: &str) -> Option<String> {
    status
        .get("manager_details")?
        .as_array()?
        .iter()
        .find(|detail| {
            detail.get("manager").and_then(Value::as_str) == Some(manager)
                && detail.get("integrity").and_then(Value::as_str) == Some("ok")
        })?
        .get("shim_path")?
        .as_str()
        .map(str::to_owned)
}

/// `Path.resolve(strict=True)`: a path that is not there resolves to nothing.
fn resolve_existing(context: &ShimContext, path: &str) -> Option<String> {
    let facts = &context.facts;
    if !facts.exists(path) {
        return None;
    }
    facts.resolve(path).ok()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    use super::super::{ShimContext, ShimFacts};
    use super::{healthy_shim_path, package_shim_digest_binding_sink, resolve_existing};

    fn facts(windows: bool) -> ShimFacts {
        ShimFacts {
            environ: BTreeMap::from([("PATH".to_owned(), String::new())]),
            home: "/Users/home".to_owned(),
            cwd: "/Users/work".to_owned(),
            executable: "/usr/bin/python3".to_owned(),
            frozen: false,
            frozen_cli: String::new(),
            trusted_frozen_cli_paths: Vec::new(),
            python_version: (3, 12),
            import_root: "/Users/src".to_owned(),
            argv0: None,
            windows,
            sqlite_connect_timeout_seconds: 30.0,
            now: "2026-01-01T00:00:00+00:00".to_owned(),
            shim_dir_transient: None,
        }
    }

    fn context(windows: bool) -> ShimContext {
        ShimContext::new(
            "/Users/home/.hol-guard",
            Some("/Users/home"),
            None,
            facts(windows),
        )
    }

    fn bound(context: &ShimContext, executable: &str, command: Option<&str>) -> bool {
        package_shim_digest_binding_sink(context, "uv", executable, command, Some(""))
            .expect("the sink answers without reading a manifest that is not there")
    }

    #[test]
    fn a_command_that_does_not_name_an_installed_shim_leaves_the_approval_with_the_user() {
        let context = context(false);
        // A bare name is resolved through PATH at launch, so it names no file.
        assert!(!bound(&context, "uv", Some("uv run tool")));
        // Nothing to compare the executable against.
        assert!(!bound(&context, "/usr/bin/uv", None));
        // The command reaches a second program, so the shim does not own it.
        assert!(!bound(
            &context,
            "/usr/bin/uv",
            Some("/usr/bin/uv run tool && curl http://example.test")
        ));
        // A bare launch, but this guard home has no shim installed at all.
        assert!(!bound(
            &context,
            "/usr/bin/uv",
            Some("/usr/bin/uv run tool")
        ));
    }

    #[test]
    fn a_windows_launch_is_left_to_the_user_rather_than_judged_by_a_posix_word_model() {
        assert!(!bound(
            &context(true),
            "C:\\shims\\uv.exe",
            Some("C:\\shims\\uv.exe run tool")
        ));
    }

    #[test]
    fn only_a_healthy_shim_for_the_named_manager_counts_as_the_binding_sink() {
        let detail = |manager: &str, integrity: &str| {
            let shim_path = format!("/shims/{manager}");
            json!({"manager": manager, "integrity": integrity, "shim_path": shim_path})
        };
        let status = |details: serde_json::Value| {
            json!({"manager_details": details})
                .as_object()
                .expect("object")
                .clone()
        };

        assert_eq!(
            healthy_shim_path(&status(json!([detail("uv", "ok")])), "uv").as_deref(),
            Some("/shims/uv")
        );
        // A stale or rewritten shim no longer binds the digest it was approved for.
        assert_eq!(
            healthy_shim_path(&status(json!([detail("uv", "modified")])), "uv"),
            None
        );
        // Another manager's healthy shim says nothing about this one.
        assert_eq!(
            healthy_shim_path(&status(json!([detail("npm", "ok")])), "uv"),
            None
        );
        assert_eq!(healthy_shim_path(&status(json!([])), "uv"), None);
        // An unreadable status shape answers no rather than guessing.
        assert_eq!(
            healthy_shim_path(&json!({}).as_object().expect("object").clone(), "uv"),
            None
        );
    }

    #[test]
    fn a_path_that_is_not_there_resolves_to_nothing() {
        let context = context(false);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("hol-guard-sink-{stamp}"));
        fs::create_dir_all(&root).expect("root");
        let present = root.join("uv");
        fs::write(&present, b"#!/bin/sh\n").expect("shim");

        assert!(resolve_existing(&context, &present.to_string_lossy()).is_some());
        assert_eq!(
            resolve_existing(&context, &root.join("gone").to_string_lossy()),
            None
        );

        fs::remove_dir_all(&root).ok();
    }
}
