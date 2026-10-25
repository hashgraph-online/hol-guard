//! Behaviour ported from the retired `tests/test_hook_source_paths.py`.
//! Those cases exercised the Python classifier against a real filesystem,
//! so they are reproduced here against real temporary trees.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::sfrs_token_vectors::NoEnvHost;

struct Workspace {
    root: std::path::PathBuf,
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Workspace {
    /// `tmp_path/home/workspace` with the `src`, `docs` and `lib` trees the
    /// retired fixture created.
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "guard-source-paths-{label}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        let workspace = root.join("home").join("workspace");
        for child in ["src", "docs", "lib"] {
            fs::create_dir_all(workspace.join(child)).unwrap();
        }
        Self { root }
    }

    fn tmp(&self) -> &Path {
        &self.root
    }

    fn home(&self) -> std::path::PathBuf {
        self.root.join("home")
    }

    fn workspace(&self) -> std::path::PathBuf {
        self.root.join("home").join("workspace")
    }

    fn write(&self, relative: &str, contents: &str) -> std::path::PathBuf {
        let path = self.workspace().join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, contents).unwrap();
        path
    }
}

fn write_file(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}

/// The `gitdir:` file a linked worktree keeps instead of a `.git` directory.
fn write_worktree_git_marker(checkout_root: &Path) {
    fs::create_dir_all(checkout_root).unwrap();
    fs::write(
        checkout_root.join(".git"),
        "gitdir: ../.git/worktrees/test-checkout\n",
    )
    .unwrap();
}

fn decide(target: &str, cwd: Option<&Path>, home: Option<&Path>) -> SourceDecision {
    decide_external(target, cwd, home, false)
}

fn decide_external(
    target: &str,
    cwd: Option<&Path>,
    home: Option<&Path>,
    allow_external_source: bool,
) -> SourceDecision {
    let host = NoEnvHost;
    let ctx = Ctx::new(&host, "/", "/");
    let cwd = cwd.map(py_path);
    let home = home.map(py_path);
    source_path_is_allowed(
        target,
        cwd.as_ref(),
        home.as_ref(),
        &ctx,
        allow_external_source,
    )
}

#[test]
fn workspace_source_files_are_allowed_with_their_reason_codes() {
    let fixture = Workspace::new("allowed");
    fixture.write("src/foo.ts", "export const x = 1;");
    fixture.write("src/component.tsx", "<div/>");
    fixture.write("src/app.py", "x = 1");
    fixture.write("docs/spec.md", "# Spec");
    fixture.write("package.json", "{}");
    fixture.write(".nvmrc", "20");
    let cwd = fixture.workspace();
    let home = fixture.home();

    for (target, reason) in [
        ("src/foo.ts", "source_prefix"),
        ("src/component.tsx", "source_prefix"),
        ("src/app.py", "source_prefix"),
        ("docs/spec.md", "source_prefix"),
        ("package.json", "source_extension"),
        (".nvmrc", "benign_source_dotfile"),
    ] {
        let decision = decide(target, Some(&cwd), Some(&home));
        assert!(decision.allowed, "{target} should be allowed");
        assert_eq!(decision.reason_code, reason, "{target}");
        assert!(decision.resolved_path.is_some(), "{target}");
    }
}

#[test]
fn credential_dotfiles_are_refused_as_sensitive_basenames() {
    let fixture = Workspace::new("secrets");
    let cwd = fixture.workspace();
    let home = fixture.home();
    for name in [".env", ".npmrc", ".netrc", ".git-credentials"] {
        fixture.write(name, "SECRET=abc");
        let decision = decide(name, Some(&cwd), Some(&home));
        assert!(!decision.allowed, "{name} should be refused");
        assert_eq!(decision.reason_code, "sensitive_basename", "{name}");
    }
}

#[test]
fn hidden_directories_are_refused_except_github_workflows() {
    let fixture = Workspace::new("hidden");
    fixture.write(".secret/data.ts", "x");
    fixture.write(".github/workflows/publish.yml", "jobs: {}\n");
    fixture.write(".github/private/config.yml", "token: fixture\n");
    let cwd = fixture.workspace();
    let home = fixture.home();

    let workflow = decide(".github/workflows/publish.yml", Some(&cwd), Some(&home));
    assert!(workflow.allowed);
    assert_eq!(workflow.reason_code, "source_extension");

    for target in [".secret/data.ts", ".github/private/config.yml"] {
        let decision = decide(target, Some(&cwd), Some(&home));
        assert!(!decision.allowed, "{target} should be refused");
        assert_eq!(decision.reason_code, "unsafe_hidden_dir", "{target}");
    }
}

#[test]
fn empty_glob_and_traversal_targets_never_resolve() {
    let fixture = Workspace::new("lexical");
    let cwd = fixture.workspace();
    let home = fixture.home();
    write_file(&fixture.tmp().join("outside.ts"), "x");

    for (target, reason) in [
        ("", "empty_path"),
        ("   ", "empty_path"),
        ("src/*.ts", "glob_pattern"),
        ("../../outside.ts", "path_traversal"),
    ] {
        let decision = decide(target, Some(&cwd), Some(&home));
        assert!(!decision.allowed, "{target:?} should be refused");
        assert_eq!(decision.reason_code, reason, "{target:?}");
    }
}

#[test]
fn an_absolute_path_outside_the_workspace_is_refused_without_the_opt_in() {
    let fixture = Workspace::new("outside");
    let outside = fixture.tmp().join("outside.ts");
    write_file(&outside, "x");

    let decision = decide(
        &outside.to_string_lossy(),
        Some(&fixture.workspace()),
        Some(&fixture.home()),
    );

    assert!(!decision.allowed);
    assert_eq!(decision.reason_code, "absolute_path_outside_workspace");
}

#[test]
fn a_symlink_anywhere_in_the_path_is_refused() {
    let fixture = Workspace::new("symlink");
    let outside = fixture.tmp().join("evil.txt");
    write_file(&outside, "secret");
    let link = fixture.workspace().join("src").join("link.ts");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let workflow_link = fixture.workspace().join(".github/workflows/publish.yml");
    fs::create_dir_all(workflow_link.parent().unwrap()).unwrap();
    let workflow_target = fixture.tmp().join("outside.yml");
    write_file(&workflow_target, "token: fixture\n");
    std::os::unix::fs::symlink(&workflow_target, &workflow_link).unwrap();

    let cwd = fixture.workspace();
    for target in [
        link.to_string_lossy().into_owned(),
        "src/link.ts".to_owned(),
        ".github/workflows/publish.yml".to_owned(),
    ] {
        let decision = decide(&target, Some(&cwd), Some(&fixture.home()));
        assert!(!decision.allowed, "{target} should be refused");
        assert_eq!(decision.reason_code, "symlink_in_path", "{target}");
    }
}

#[test]
fn an_external_sibling_checkout_is_allowed_only_with_the_opt_in() {
    let fixture = Workspace::new("external-ok");
    let worktree_root = fixture.home().join("sibling-source");
    let worktree_file = worktree_root.join("scripts").join("guard-test");
    write_file(&worktree_file, "#!/bin/sh\n");
    write_worktree_git_marker(&worktree_root);

    let repository_root = fixture.home().join("sibling-repository");
    let repository_file = repository_root.join("src").join("main.py");
    write_file(&repository_file, "value = 1\n");
    fs::create_dir_all(repository_root.join(".git")).unwrap();

    let cwd = fixture.workspace();
    let home = fixture.home();
    for file in [&worktree_file, &repository_file] {
        let target = file.to_string_lossy();
        let refused = decide(&target, Some(&cwd), Some(&home));
        assert!(!refused.allowed, "{target} needs the opt-in");
        assert_eq!(refused.reason_code, "absolute_path_outside_workspace");

        let decision = decide_external(&target, Some(&cwd), Some(&home), true);
        assert!(decision.allowed, "{target} should be allowed");
        assert_eq!(decision.reason_code, "external_source_path", "{target}");
    }
}

#[test]
fn an_external_target_must_be_an_immediate_sibling_inside_a_resolvable_home() {
    let fixture = Workspace::new("external-bounds");
    let nested = fixture.home().join("Downloads").join("app");
    let nested_file = nested.join("src").join("main.py");
    write_file(&nested_file, "value = 1\n");
    fs::create_dir_all(nested.join(".git")).unwrap();

    let outside_home = fixture.tmp().join("outside-home").join("scripts");
    let outside_file = outside_home.join("guard-test");
    write_file(&outside_file, "#!/bin/sh\n");

    let sibling_root = fixture.home().join("sibling-source");
    let sibling_file = sibling_root.join("scripts").join("guard-test");
    write_file(&sibling_file, "#!/bin/sh\n");
    write_worktree_git_marker(&sibling_root);

    let cwd = fixture.workspace();
    let home = fixture.home();
    let missing_home = fixture.tmp().join("missing-home");

    let nested_decision = decide_external(
        &nested_file.to_string_lossy(),
        Some(&cwd),
        Some(&home),
        true,
    );
    assert!(!nested_decision.allowed);
    assert_eq!(
        nested_decision.reason_code,
        "external_target_not_sibling_git_checkout"
    );

    let outside_decision = decide_external(
        &outside_file.to_string_lossy(),
        Some(&cwd),
        Some(&home),
        true,
    );
    assert!(!outside_decision.allowed);
    assert_eq!(outside_decision.reason_code, "external_target_outside_home");

    let unresolvable = decide_external(
        &sibling_file.to_string_lossy(),
        Some(&cwd),
        Some(&missing_home),
        true,
    );
    assert!(!unresolvable.allowed);
    assert_eq!(unresolvable.reason_code, "external_home_unavailable");
}

#[test]
fn an_external_target_without_a_home_is_refused() {
    let fixture = Workspace::new("external-no-home");
    let sibling_root = fixture.home().join("sibling-source");
    let sibling_file = sibling_root.join("scripts").join("guard-test");
    write_file(&sibling_file, "#!/bin/sh\n");
    write_worktree_git_marker(&sibling_root);

    let decision = decide_external(
        &sibling_file.to_string_lossy(),
        Some(&fixture.workspace()),
        None,
        true,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason_code, "external_home_unavailable");
}

#[test]
fn the_external_opt_in_never_admits_a_relative_escape_or_a_symlink() {
    let fixture = Workspace::new("external-escape");
    let escape_root = fixture.home().join("external-source").join("scripts");
    write_file(&escape_root.join("guard-test"), "#!/bin/sh\n");

    let sibling_root = fixture.home().join("sibling-source");
    let real_file = sibling_root.join("scripts").join("guard-test");
    write_file(&real_file, "#!/bin/sh\n");
    write_worktree_git_marker(&sibling_root);
    let link = sibling_root.join("scripts").join("linked-guard-test");
    std::os::unix::fs::symlink(&real_file, &link).unwrap();

    let cwd = fixture.workspace();
    let home = fixture.home();

    let escaped = decide_external(
        "../external-source/scripts/guard-test",
        Some(&cwd),
        Some(&home),
        true,
    );
    assert!(!escaped.allowed);
    assert_eq!(escaped.reason_code, "path_traversal");

    let linked = decide_external(&link.to_string_lossy(), Some(&cwd), Some(&home), true);
    assert!(!linked.allowed);
    assert_eq!(linked.reason_code, "symlink_in_path");
}

#[test]
fn external_sensitive_names_are_refused_without_substring_false_positives() {
    let fixture = Workspace::new("external-names");
    let sibling_root = fixture.home().join("sibling-source");
    write_worktree_git_marker(&sibling_root);
    let cwd = fixture.workspace();
    let home = fixture.home();

    let credential_file = sibling_root.join("credentials").join("config.ts");
    write_file(&credential_file, "credential = 'value'\n");
    let decision = decide_external(
        &credential_file.to_string_lossy(),
        Some(&cwd),
        Some(&home),
        true,
    );
    assert!(!decision.allowed);
    assert_eq!(decision.reason_code, "sensitive_basename");

    for name in ["secrets.json", "credentials.yaml", "auth_token.ts"] {
        let path = sibling_root.join(name);
        write_file(&path, "value = 1\n");
        let decision = decide_external(&path.to_string_lossy(), Some(&cwd), Some(&home), true);
        assert!(!decision.allowed, "{name} should be refused");
        assert_eq!(decision.reason_code, "sensitive_basename", "{name}");
    }

    for name in ["authentication.ts", "tokenizer.ts", "secretary.ts"] {
        let path = sibling_root.join(name);
        write_file(&path, "value = 1\n");
        let decision = decide_external(&path.to_string_lossy(), Some(&cwd), Some(&home), true);
        assert!(decision.allowed, "{name} should be allowed");
        assert_eq!(decision.reason_code, "external_source_path", "{name}");
    }
}

#[test]
fn path_contains_symlink_reports_links_and_escapes() {
    let fixture = Workspace::new("contains-symlink");
    let workspace = py_path(&fixture.workspace());
    let target = fixture.tmp().join("evil.txt");
    write_file(&target, "secret");
    let link = fixture.workspace().join("link.ts");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let plain = fixture.write("src/foo.ts", "x");
    let outside = fixture.tmp().join("outside.ts");
    write_file(&outside, "x");

    assert!(path_contains_symlink(&py_path(&link), &workspace));
    assert!(!path_contains_symlink(&py_path(&plain), &workspace));
    assert!(path_contains_symlink(&py_path(&outside), &workspace));
}

#[test]
fn candidate_resolution_follows_the_working_directory_and_home() {
    let fixture = Workspace::new("resolve");
    let host = NoEnvHost;
    let ctx = Ctx::new(&host, "/", "/");
    let workspace = py_path(&fixture.workspace());
    let home = py_path(&fixture.home());

    let relative = resolve_source_candidate_path("src/foo.ts", Some(&workspace), None, &ctx);
    assert_eq!(relative, Some(workspace.join("src").join("foo.ts")));

    let absolute_text = fixture.tmp().join("foo.ts").to_string_lossy().into_owned();
    let absolute = resolve_source_candidate_path(&absolute_text, None, None, &ctx);
    assert_eq!(absolute, Some(PyPath::new(&absolute_text)));

    let tilde = resolve_source_candidate_path("~/foo.ts", None, Some(&home), &ctx);
    assert_eq!(tilde, Some(home.join("foo.ts")));

    assert_eq!(resolve_source_candidate_path("", None, None, &ctx), None);
}

#[test]
fn a_tilde_path_without_a_home_does_not_resolve() {
    let fixture = Workspace::new("resolve-no-home");
    let host = NoEnvHost;
    let ctx = Ctx::new(&host, "/", "/");
    let workspace = py_path(&fixture.workspace());

    assert_eq!(
        resolve_source_candidate_path("~/foo.ts", Some(&workspace), None, &ctx),
        None
    );
    assert_eq!(
        resolve_source_candidate_path("~", Some(&workspace), None, &ctx),
        None
    );
}
