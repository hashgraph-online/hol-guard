//! Operand safety for a staged diff written without the `--` separator.

use crate::codex_output_env::{Ctx, GitCheck, InspectionHost};
use crate::sfrs_git_cached_diff::{cached_diff_operand_directory, cached_diff_operands_are_safe};
use guard_contracts::CompoundGitSegmentV1;
use std::path::{Path, PathBuf};

/// Accepts the pathspecs the resident host accepts: repository-relative names.
struct Host;

impl InspectionHost for Host {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn cached_diff_pathspecs(&self, values: &[String]) -> bool {
        !values.is_empty()
            && values.iter().all(|value| {
                !value.is_empty()
                    && !value.starts_with(['-', '/', '~'])
                    && !value.split('/').any(|component| component == "..")
            })
    }
    fn git_inspection_segment(&self, _: &CompoundGitSegmentV1, _: Option<&str>) -> bool {
        true
    }
    fn git_show_config(&self, _: &CompoundGitSegmentV1, _: Option<&str>) -> bool {
        true
    }
    fn standalone_git_routine(&self, _: &[CompoundGitSegmentV1], _: bool, _: Option<&str>) -> bool {
        false
    }
}

/// A working tree holding the names the bare form is allowed to read: the
/// operand check asks the filesystem the question git asks it.
struct Workspace(PathBuf);

impl Workspace {
    fn new(name: &str) -> Self {
        let unique = format!("hol-guard-cached-diff-{}-{name}", std::process::id());
        let root = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).expect("workspace");
        std::fs::write(root.join("package.json"), "{}\n").expect("manifest");
        std::fs::write(root.join("src").join("app.ts"), "export const a = 1;\n").expect("source");
        Self(root)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn safe_in(cwd: Option<&Path>, operands: &[&str]) -> bool {
    let host = Host;
    let ctx = Ctx::new(&host, "/", "/");
    let args: Vec<String> = operands.iter().map(|item| (*item).to_owned()).collect();
    cached_diff_operands_are_safe(&args, cwd, &ctx)
}

#[test]
fn bare_pathspecs_read_the_index_like_the_separator_form() {
    let workspace = Workspace::new("present");
    let cwd = Some(workspace.path());
    assert!(safe_in(cwd, &["--cached", "package.json"]));
    assert!(safe_in(cwd, &["--cached", "src"]));
    assert!(safe_in(cwd, &["--staged", "src/app.ts", "package.json"]));
    assert!(safe_in(cwd, &["--cached", "HEAD", "package.json"]));
    assert!(safe_in(cwd, &["--cached", "--stat", "src"]));
}

#[test]
fn a_bare_operand_that_is_not_in_the_tree_stays_a_review() {
    // `git diff --cached origin/main` diffs the index against a ref, which the
    // `--` form never admits. Nothing of that name is in the tree, so git would
    // read it as a revision and the bare form has to refuse it.
    let workspace = Workspace::new("absent");
    let cwd = Some(workspace.path());
    assert!(!safe_in(cwd, &["--cached", "main"]));
    assert!(!safe_in(cwd, &["--cached", "origin/main"]));
    assert!(!safe_in(cwd, &["--cached", "feature/x", "package.json"]));
    assert!(!safe_in(cwd, &["--cached", "src/missing.ts"]));
    // An unresolved cwd cannot answer the question, so it refuses as well.
    assert!(!safe_in(None, &["--cached", "package.json"]));
}

#[test]
fn operand_free_and_separator_forms_keep_their_answers() {
    let workspace = Workspace::new("forms");
    let cwd = Some(workspace.path());
    assert!(safe_in(cwd, &["--cached"]));
    assert!(safe_in(cwd, &["--cached", "--name-only"]));
    assert!(safe_in(cwd, &["--cached", "--", "package.json"]));
    // The separator names its own pathspecs, so it answers without a cwd.
    assert!(safe_in(None, &["--cached", "--", "package.json"]));
    assert!(!safe_in(cwd, &["--name-only"]));
    assert!(!safe_in(cwd, &["--cached", "--", "../outside"]));
}

#[test]
fn an_unlisted_option_never_reaches_the_pathspec_check() {
    let workspace = Workspace::new("options");
    let cwd = Some(workspace.path());
    assert!(!safe_in(cwd, &["--cached", "--output=/tmp/leak.diff"]));
    assert!(!safe_in(cwd, &["--cached", "-O/tmp/order"]));
    assert!(!safe_in(cwd, &["--cached", "--ext-diff"]));
    assert!(!safe_in(cwd, &["--cached", "../outside"]));
    assert!(!safe_in(cwd, &["--cached", "/etc/passwd"]));
}

#[test]
fn the_pathspec_count_stays_bounded() {
    let workspace = Workspace::new("bounded");
    let mut operands = vec!["--cached".to_owned()];
    operands.extend((0..17).map(|index| format!("src/file{index}.ts")));
    let host = Host;
    let ctx = Ctx::new(&host, "/", "/");
    let cwd = Some(workspace.path());
    assert!(!cached_diff_operands_are_safe(&operands, cwd, &ctx));
}

#[test]
fn a_routed_read_resolves_its_operands_where_git_enters() {
    let workspace = Workspace::new("routed");
    let outer = workspace.path();
    let inner = outer.join("inner");
    // `release` lives inside the directory `-C` enters, not beside the shell's
    // own working directory, where git would read the same word as a revision.
    std::fs::create_dir_all(inner.join("release")).expect("route target");
    let routed = |route: &str| {
        ["git", "-C", route, "diff", "--cached", "release"]
            .iter()
            .map(|item| (*item).to_owned())
            .collect::<Vec<String>>()
    };

    assert_eq!(
        cached_diff_operand_directory(&routed("inner"), Some(outer)),
        Some(inner.clone())
    );
    assert_eq!(
        cached_diff_operand_directory(&routed(&inner.to_string_lossy()), Some(outer)),
        Some(inner.clone())
    );
    let unrouted: Vec<String> = ["git", "diff", "--cached", "release"]
        .iter()
        .map(|item| (*item).to_owned())
        .collect();
    assert_eq!(
        cached_diff_operand_directory(&unrouted, Some(outer)),
        Some(outer.to_path_buf())
    );

    assert!(safe_in(Some(&inner), &["--cached", "release"]));
    assert!(!safe_in(Some(outer), &["--cached", "release"]));
}
