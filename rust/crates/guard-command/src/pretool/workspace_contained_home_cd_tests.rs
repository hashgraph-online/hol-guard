//! Each guard the home projection applies, named one at a time.
//!
//! `as_absolute_cd` answers `None` for every spelling it cannot prove, so a
//! single failed projection says nothing about which proof refused it. The
//! steps below ask them in order, so a change that moves one of them points
//! at itself rather than at the whole projection.
use super::super::super::{directory_targets, PathContext};
use super::as_absolute_cd;
use crate::CommandModelRequestV1;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// A home with a checkout and a sibling worktree below it, spelled the way
/// the host reports them.
fn fixture() -> (PathBuf, PathBuf, PathBuf) {
    let root = Path::new("/tmp").join(format!(
        "guard-home-cd-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    let projects = root.join("home/projects");
    std::fs::create_dir_all(projects.join("app")).unwrap();
    std::fs::create_dir_all(projects.join("app-report/tools")).unwrap();
    let home = root.join("home").canonicalize().unwrap();
    (
        home.clone(),
        home.join("projects/app").canonicalize().unwrap(),
        home.join("projects/app-report").canonicalize().unwrap(),
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

#[cfg(unix)]
#[test]
fn every_guard_the_home_projection_applies_admits_a_plain_cd() {
    let (home, main, _tree) = fixture();
    let command = "cd ~/projects/app-report && ./tools/report 2>&1 | tail -15";
    let context = PathContext {
        home_dir: home.to_str(),
        cwd: main.to_str(),
        shell_home_matches: true,
        cdpath_unset: false,
        rustup_override_absent: false,
        npm_config_inert: false,
        pip_config_inert: false,
        ripgrep_config_absent: false,
        psql_environment: Default::default(),
        creates_nothing: false,
    };
    let model = parse(command);
    assert_eq!(model.confidence, "exact", "confidence");
    assert!(!model.path_overridden, "path_overridden");
    assert!(model.wrapper_chain.is_empty(), "model wrapper chain");
    let first = model.segments.first().expect("a first segment");
    assert_eq!(first.executable.as_deref(), Some("cd"), "executable");
    assert_eq!(first.pipeline_index, 0, "pipeline index");
    assert!(first.environment_names.is_empty(), "environment names");
    assert!(first.wrapper_chain.is_empty(), "segment wrapper chain");
    assert!(!first.path_overridden, "segment path overridden");
    assert_eq!(
        first.arguments,
        vec!["~/projects/app-report".to_owned()],
        "arguments"
    );
    assert!(
        directory_targets::home_targets_unquoted(first),
        "home targets unquoted: {}",
        first.text
    );
    let chars: Vec<char> = model.normalized_text.chars().collect();
    let source: String = chars[first.span.start..first.span.end].iter().collect();
    assert_eq!(source, "cd ~/projects/app-report", "segment source");
    assert_eq!(
        directory_targets::verified_cwd_target("~/projects/app-report", context).as_deref(),
        home.join("projects/app-report").to_str(),
        "verified target"
    );
    let projected = as_absolute_cd(&model, context).expect("a projected list");
    assert_eq!(
        projected.text,
        format!(
            "cd {} && ./tools/report 2>&1 | tail -15",
            home.join("projects/app-report").display()
        ),
        "projected text"
    );
    let _ = std::fs::remove_dir_all(home.parent().unwrap());
}
