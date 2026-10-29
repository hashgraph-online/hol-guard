//! Each guard the launcher projection applies, named one at a time.
//!
//! `as_absolute_program` answers `None` for every spelling it cannot prove,
//! so a single failed projection says nothing about which proof refused it.
//! The steps below ask them in order, so a change that moves one of them
//! points at itself rather than at the whole projection.
use super::super::super::PathContext;
use super::as_absolute_program;
use crate::CommandModelRequestV1;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// A home with a launcher installed below it and a checkout beside it,
/// spelled the way the host reports them.
fn fixture() -> (PathBuf, PathBuf) {
    // `/tmp`, not `$TMPDIR`: macOS puts the latter below `/private/var`,
    // which the path proofs judge as its own location rather than a home.
    let root = Path::new("/tmp").join(format!(
        "guard-home-exec-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("home/.local/bin")).unwrap();
    std::fs::create_dir_all(root.join("home/projects/app")).unwrap();
    let home = root.join("home").canonicalize().unwrap();
    std::fs::write(
        home.join(".local/bin/run-queued"),
        "#!/bin/sh\nexec \"$@\"\n",
    )
    .unwrap();
    (
        home.clone(),
        home.join("projects/app").canonicalize().unwrap(),
    )
}

fn parse(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "test".into(),
    })
    .unwrap()
}

fn context<'a>(home: &'a Path, cwd: &'a Path, shell_home_matches: bool) -> PathContext<'a> {
    PathContext {
        home_dir: home.to_str(),
        cwd: cwd.to_str(),
        shell_home_matches,
        cdpath_unset: false,
        rustup_override_absent: false,
        npm_config_inert: false,
        pip_config_inert: false,
        ripgrep_config_absent: false,
        psql_environment: Default::default(),
        creates_nothing: false,
    }
}

#[cfg(unix)]
#[test]
fn every_guard_the_launcher_projection_applies_admits_a_home_spelled_launcher() {
    let (home, cwd) = fixture();
    let command = "~/.local/bin/run-queued -- npx vitest run __tests__/unit.test.ts";
    let model = parse(command);
    assert_eq!(model.confidence, "exact", "confidence");
    assert!(!model.path_overridden, "path_overridden");
    assert!(model.wrapper_chain.is_empty(), "model wrapper chain");
    let first = model.segments.first().expect("a first segment");
    assert_eq!(
        first.executable.as_deref(),
        Some("~/.local/bin/run-queued"),
        "executable"
    );
    assert_eq!(first.pipeline_index, 0, "pipeline index");
    assert!(first.environment_names.is_empty(), "environment names");
    assert!(first.wrapper_chain.is_empty(), "segment wrapper chain");
    assert!(!first.path_overridden, "segment path overridden");
    let chars: Vec<char> = model.normalized_text.chars().collect();
    let source: String = chars[first.span.start..first.span.end].iter().collect();
    assert_eq!(source, command, "segment source");
    let projected =
        as_absolute_program(&model, context(&home, &cwd, true)).expect("a projected command");
    assert_eq!(
        projected.text,
        format!(
            "{} -- npx vitest run __tests__/unit.test.ts",
            home.join(".local/bin/run-queued").display()
        ),
        "projected text"
    );
    assert_eq!(
        projected
            .model
            .segments
            .first()
            .unwrap()
            .executable
            .as_deref(),
        home.join(".local/bin/run-queued").to_str(),
        "projected executable"
    );
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// A shell whose HOME is not the declared one expands `~` somewhere else,
/// so the spelling proves nothing and keeps its review.
#[cfg(unix)]
#[test]
fn a_shell_home_the_harness_did_not_declare_is_not_projected() {
    let (home, cwd) = fixture();
    let model = parse("~/.local/bin/run-queued -- npx vitest run __tests__/unit.test.ts");
    assert!(
        as_absolute_program(&model, context(&home, &cwd, false)).is_none(),
        "an undeclared shell home"
    );
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// A quoted `~` stays a literal relative path that names a different file,
/// so it is never rewritten into the home it looks like.
#[cfg(unix)]
#[test]
fn a_quoted_launcher_is_not_projected() {
    let (home, cwd) = fixture();
    let model = parse("'~/.local/bin/run-queued' -- npx vitest run __tests__/unit.test.ts");
    assert!(
        as_absolute_program(&model, context(&home, &cwd, true)).is_none(),
        "a quoted launcher"
    );
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// `~+`, `~-` and `~N` name the directory stack rather than home, and a
/// launcher that is not installed is not the one the agent named.
#[cfg(unix)]
#[test]
fn a_directory_stack_or_missing_launcher_is_not_projected() {
    let (home, cwd) = fixture();
    for command in [
        "~+/.local/bin/run-queued -- npx vitest run __tests__/unit.test.ts",
        "~-/.local/bin/run-queued -- npx vitest run __tests__/unit.test.ts",
        "~1/.local/bin/run-queued -- npx vitest run __tests__/unit.test.ts",
        "~/.local/bin/absent -- npx vitest run __tests__/unit.test.ts",
        "~/.local/bin/../../../etc/run-queued -- npx vitest run __tests__/unit.test.ts",
    ] {
        let model = parse(command);
        assert!(
            as_absolute_program(&model, context(&home, &cwd, true)).is_none(),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// An agent that steps into a subdirectory first still spells the launcher
/// from home, so the projection reaches a segment after the `cd`.
#[cfg(unix)]
#[test]
fn a_launcher_after_a_cd_is_projected() {
    let (home, cwd) = fixture();
    let model = parse("cd app && ~/.local/bin/run-queued -- npx vitest run");
    let projected =
        as_absolute_program(&model, context(&home, &cwd, true)).expect("a projected command");
    assert_eq!(
        projected.text,
        format!(
            "cd app && {} -- npx vitest run",
            home.join(".local/bin/run-queued").display()
        ),
        "projected text"
    );
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}

/// A word before the launcher means the shell reaches it through something
/// else, which the projection does not answer for.
#[cfg(unix)]
#[test]
fn a_prefixed_launcher_is_not_projected() {
    let (home, cwd) = fixture();
    for command in [
        "NODE_ENV=test ~/.local/bin/run-queued -- npx vitest run",
        "env ~/.local/bin/run-queued -- npx vitest run",
        "echo hi | ~/.local/bin/run-queued -- npx vitest run",
    ] {
        let model = parse(command);
        assert!(
            as_absolute_program(&model, context(&home, &cwd, true)).is_none(),
            "{command}"
        );
    }
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}
