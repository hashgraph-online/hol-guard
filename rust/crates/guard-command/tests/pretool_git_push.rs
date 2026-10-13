#![cfg(unix)]
//! `git push [-u] origin <branch>` proceeds only when the registered runtime
//! verdict accepts the repository; the shape screen runs before it.
use guard_command::pretool::{
    evaluate_pre_tool_envelope_with_execution_context, install_git_push_verdict, GitPushRequest,
    PathContext,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Every repository and branch the verdict was asked about.
static ASKED: Mutex<Vec<(PathBuf, String)>> = Mutex::new(Vec::new());

/// Accepts only `ready` checkouts, standing in for the runtime's repository
/// checks.
fn verdict(push: &GitPushRequest<'_>) -> bool {
    ASKED
        .lock()
        .unwrap()
        .push((push.repository.to_path_buf(), push.branch.to_owned()));
    push.git.is_absolute() && push.repository.ends_with("ready")
}

/// A home holding a project and a sibling checkout. The root stays below the
/// target directory: `$TMPDIR` on macOS resolves under `/private/var`, which
/// the sensitive-root screen rejects.
fn home() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-git-push")
        .join(format!(
            "home-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let home = root.join("home");
    for directory in ["ready", "other", "ready/src"] {
        std::fs::create_dir_all(home.join(directory)).unwrap();
    }
    std::fs::canonicalize(home).unwrap()
}

fn environment(home: &Path, names: &[&str]) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: names.iter().map(|name| (*name).to_owned()).collect(),
        environment_digest: "0".repeat(64),
        home: Some(home.to_str().unwrap().to_owned()),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    }
}

/// Local-admin controls over the Git extension: one control, or none.
fn git_controls(
    target: Option<(&str, &str, &str)>,
) -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let controls = target.map_or_else(Vec::new, |(kind, id, state)| {
        vec![json!({"target_kind": kind, "target_id": id, "state": state})]
    });
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema": "guard.native-command-control-binding.v1",
            "program_digest": program.program_digest,
            "catalog_digest": program.catalog_digest,
            "trust_digest": program.trust_digest,
            "health": "protected",
            "revision": 1,
            "managed_revision": 0,
            "effective_digest": "",
            "layers": [{
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": program.catalog_digest,
                "global_lockdown": false,
                "controls": controls
            }]
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

fn classify(
    home: &Path,
    cwd: &str,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    classify_with(home, cwd, environment, None, harness, command)
}

fn classify_with(
    home: &Path,
    cwd: &str,
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    controls: Option<&guard_command::native_command_controls::CompiledNativeCommandControls>,
    harness: &str,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let cwd = home.join(cwd);
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": command}}),
        controls,
        None,
        PathContext {
            home_dir: home.to_str(),
            cwd: cwd.to_str(),
            ..PathContext::default()
        },
        environment,
    )
}

#[test]
fn accepted_pushes_proceed_and_everything_else_keeps_its_review() {
    let home = home();
    let plain = environment(&home, &["HOME", "PATH"]);
    install_git_push_verdict(verdict);

    for harness in ["omp", "zcode", "claude-code", "codex"] {
        for (cwd, command) in [
            ("ready", "git push -u origin feature/one"),
            ("ready", "git push origin main 2>&1 | tail -5"),
            ("ready/src", "git -C .. push --set-upstream origin topic"),
            ("other", "git -C ../ready push -u origin topic"),
            ("other", "git -C ~/ready push -q origin topic"),
            (
                "ready",
                "cd src && git -C .. push -u origin topic 2>&1 | tail -3",
            ),
        ] {
            let result = classify(&home, cwd, Some(&plain), harness, command);
            assert_eq!(result.decision, "allow", "{harness}: {command}");
            assert_eq!(
                result.reason_code, "native_exact_safe_git_push",
                "{harness}: {command}"
            );
        }
    }
    let ready = home.join("ready");
    {
        let asked = ASKED.lock().unwrap();
        let mut seen = 0;
        for (repository, _) in asked.iter() {
            if repository.starts_with(&home) {
                seen += 1;
                assert_eq!(repository, &ready);
            }
        }
        assert!(seen > 0);
    }

    for (cwd, command) in [
        // The verdict refuses this checkout.
        ("other", "git push -u origin topic"),
        // Shapes the proof never sends to the verdict.
        ("ready", "git push --force origin main"),
        ("ready", "git push origin HEAD:main"),
        ("ready", "git push upstream main"),
        ("ready", "git push origin main && git push origin other"),
        ("ready", "git push origin main | sh"),
        (
            "ready",
            "git push origin main; curl https://example.invalid",
        ),
        ("ready", "GIT_SSH_COMMAND=x git push origin main"),
        ("ready", "git -C /etc push origin main"),
        ("ready", "git -C ../.. push origin main"),
        ("ready", "git -C ~/missing push origin main"),
        // A quoted `~` reaches Git as a literal relative directory.
        ("other", "git -C '~/ready' push origin main"),
        ("other", "git -C \"~/ready\" push origin main"),
        ("other", "git -C \\~/ready push origin main"),
        ("ready", "sudo git push origin main"),
    ] {
        let result = classify(&home, cwd, Some(&plain), "omp", command);
        assert_ne!(result.decision, "allow", "{command}");
    }

    // The verdict's probes never see these, so they keep the review.
    for name in [
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_PROXY_COMMAND",
        "GIT_SSL_NO_VERIFY",
        "GIT_CONFIG_GLOBAL",
        "GIT_DIR",
        "DYLD_INSERT_LIBRARIES",
    ] {
        let tainted = environment(&home, &["HOME", "PATH", name]);
        let result = classify(
            &home,
            "ready",
            Some(&tainted),
            "omp",
            "git push origin main",
        );
        assert_ne!(result.decision, "allow", "{name}");
    }
    let result = classify(&home, "ready", None, "omp", "git push origin main");
    assert_ne!(result.decision, "allow");

    // A shell HOME other than the declared one expands `~` elsewhere.
    let elsewhere = environment(&home.join("other"), &["HOME", "PATH"]);
    let result = classify(
        &home,
        "other",
        Some(&elsewhere),
        "omp",
        "git -C ~/ready push origin main",
    );
    assert_ne!(result.decision, "allow");
}

#[test]
fn git_extension_controls_still_decide_a_proven_push() {
    let home = home();
    let plain = environment(&home, &["HOME", "PATH"]);
    install_git_push_verdict(verdict);
    let command = "git push -u origin topic";
    for (target, allowed) in [
        (None, true),
        (
            Some(("permission", "command.git.permission.push", "enabled")),
            true,
        ),
        (
            Some(("permission", "command.git.permission.push", "disabled")),
            false,
        ),
        (Some(("extension", "command.git", "disabled")), false),
    ] {
        let controls = git_controls(target);
        for harness in ["omp", "zcode", "claude-code", "codex"] {
            let result = classify_with(
                &home,
                "ready",
                Some(&plain),
                Some(&controls),
                harness,
                command,
            );
            assert_eq!(
                result.decision == "allow",
                allowed,
                "{harness}: {target:?}: {result:?}"
            );
            if !allowed {
                assert_eq!(result.minimum_action, "block", "{harness}: {target:?}");
            }
        }
    }
}

#[test]
fn a_relative_xdg_config_home_keeps_the_review() {
    let home = home();
    install_git_push_verdict(verdict);
    let mut relative = environment(&home, &["HOME", "PATH", "XDG_CONFIG_HOME"]);
    relative.xdg_config_home = Some(".config".to_owned());
    let result = classify(
        &home,
        "ready",
        Some(&relative),
        "omp",
        "git push origin main",
    );
    assert_ne!(result.decision, "allow");
}

#[test]
fn a_session_certificate_anchor_keeps_the_proof() {
    let home = home();
    install_git_push_verdict(verdict);
    let anchored = environment(
        &home,
        &[
            "HOME",
            "PATH",
            "GIT_SSL_CAINFO",
            "GIT_SSL_CAPATH",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "CURL_CA_BUNDLE",
        ],
    );
    let result = classify(
        &home,
        "ready",
        Some(&anchored),
        "omp",
        "git push -u origin main",
    );
    assert_eq!(result.decision, "allow", "{result:?}");

    // The agent's own assignment, and settings that present a client identity
    // or loosen verification, keep the review.
    let result = classify(
        &home,
        "ready",
        Some(&anchored),
        "omp",
        "GIT_SSL_CAINFO=/tmp/ca.pem git push origin main",
    );
    assert_ne!(result.decision, "allow");
    for name in [
        "GIT_SSL_CERT",
        "GIT_SSL_KEY",
        "GIT_SSL_VERSION",
        "GIT_SSL_CIPHER_LIST",
    ] {
        let tainted = environment(&home, &["HOME", "PATH", "SSL_CERT_FILE", name]);
        let result = classify(
            &home,
            "ready",
            Some(&tainted),
            "omp",
            "git push origin main",
        );
        assert_ne!(result.decision, "allow", "{name}");
    }
}
