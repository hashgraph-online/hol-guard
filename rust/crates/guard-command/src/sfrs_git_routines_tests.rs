//! The branch a one-word `checkout`/`switch` names, `-` among them.
//!
//! The cases answer the proof's probes with a real temporary checkout, and
//! the proof reads every path it is handed as a `PurePosixPath`, so a
//! Windows temp root is not absolute to it and the hook and git-dir
//! comparisons never line up. `lib.rs` builds this module on unix only, the
//! way it already does for the other proofs that question a real tree.

use std::path::{Path, PathBuf};

use crate::codex_output_env::{Ctx, GitCheck, GitProbe, InspectionHost};
use crate::sfrs_git_routines::{git_local_branch_switch_is_safe, previous_branch_name};

/// A checkout the proof can question: it holds `main`, keeps no post-checkout
/// hook, and answers `@{-1}` with whatever the case asks it to.
struct Host {
    root: PathBuf,
    previous: (i32, String),
}

impl InspectionHost for Host {
    fn env(&self, _: &str) -> Option<String> {
        None
    }
    fn git_executable(&self) -> Option<String> {
        Some(self.text(&self.root.join("bin").join("git")))
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        true
    }
    fn git_probe(&self, _: &str, args: &[String], _: &str) -> Option<GitProbe> {
        let row = |code: i32, stdout: String| {
            Some(GitProbe {
                code,
                stdout,
                stderr: String::new(),
            })
        };
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        match words.as_slice() {
            ["rev-parse", "--symbolic-full-name", "@{-1}"] => {
                let (code, stdout) = self.previous.clone();
                row(code, stdout)
            }
            ["rev-parse", "--verify", "--quiet", reference] => {
                let known = *reference == "refs/heads/main^{commit}";
                row(
                    i32::from(!known),
                    if known {
                        "a1b2c3\n".to_owned()
                    } else {
                        String::new()
                    },
                )
            }
            // No branch configuration, which `--get-regexp` reports as a miss.
            ["config", "--null", "--get-regexp", _] => row(1, String::new()),
            ["rev-parse", "--git-path", "hooks/post-checkout"] => {
                row(0, self.text(&self.root.join(".git/hooks/post-checkout")))
            }
            ["rev-parse", "--absolute-git-dir"] => row(0, self.text(&self.root.join(".git"))),
            _ => row(128, String::new()),
        }
    }
}

impl Host {
    fn text(&self, path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }
}

/// The repository tree the probes describe, removed with the case.
struct Checkout(PathBuf);

impl Checkout {
    fn new(name: &str) -> Self {
        let base = std::fs::canonicalize(std::env::temp_dir()).expect("temp dir");
        let root = base.join(format!("hol-guard-switch-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".git").join("hooks")).expect("git dir");
        std::fs::create_dir_all(root.join("bin")).expect("bin");
        std::fs::write(root.join("bin").join("git"), "#!/bin/sh\n").expect("git");
        Self(root)
    }
}

impl Drop for Checkout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn switches_to(target: &str, previous: (i32, &str), checkout: &Checkout) -> bool {
    let host = Host {
        root: checkout.0.clone(),
        previous: (previous.0, previous.1.to_owned()),
    };
    let ctx = Ctx::new(&host, "/", "/");
    let args = vec!["switch".to_owned(), target.to_owned()];
    git_local_branch_switch_is_safe(&args, &checkout.0, &ctx)
}

const LEFT_MAIN: (i32, &str) = (0, "refs/heads/main\n");

#[test]
fn the_branch_git_left_last_is_the_branch_it_returns_to() {
    let checkout = Checkout::new("returns");
    assert!(switches_to("-", LEFT_MAIN, &checkout));
    assert!(switches_to("main", LEFT_MAIN, &checkout));
    let host = Host {
        root: checkout.0.clone(),
        previous: (LEFT_MAIN.0, LEFT_MAIN.1.to_owned()),
    };
    let ctx = Ctx::new(&host, "/", "/");
    let checkout_dash = vec!["checkout".to_owned(), "-".to_owned()];
    assert!(git_local_branch_switch_is_safe(
        &checkout_dash,
        &checkout.0,
        &ctx
    ));
}

#[test]
fn a_dash_git_cannot_read_as_a_local_branch_keeps_its_review() {
    let checkout = Checkout::new("unread");
    // A commit rather than a branch: `rev-parse` prints nothing and succeeds.
    assert!(!switches_to("-", (0, ""), &checkout));
    // No reflog to read, so there is no previous branch at all.
    assert!(!switches_to("-", (128, ""), &checkout));
    // A branch the repository no longer holds.
    assert!(!switches_to("-", (0, "refs/heads/gone\n"), &checkout));
    // A remote-tracking ref is not a branch this checkout can enter.
    assert!(!switches_to(
        "-",
        (0, "refs/remotes/origin/main\n"),
        &checkout
    ));
}

#[test]
fn every_other_leading_dash_is_an_option_the_proof_does_not_read() {
    let checkout = Checkout::new("options");
    assert!(!switches_to("--detach", LEFT_MAIN, &checkout));
    assert!(!switches_to("-c", LEFT_MAIN, &checkout));
    assert!(!switches_to("--", LEFT_MAIN, &checkout));
    assert!(!switches_to(".", LEFT_MAIN, &checkout));
    assert!(!switches_to("", LEFT_MAIN, &checkout));
}

#[test]
fn the_previous_branch_is_read_from_the_full_ref_name() {
    let probe = |code: i32, stdout: &str| GitProbe {
        code,
        stdout: stdout.to_owned(),
        stderr: String::new(),
    };
    assert_eq!(
        previous_branch_name(&probe(0, "refs/heads/feat/retry\n")).as_deref(),
        Some("feat/retry")
    );
    assert_eq!(
        previous_branch_name(&probe(0, "refs/heads/main")).as_deref(),
        Some("main")
    );
    assert_eq!(previous_branch_name(&probe(1, "refs/heads/main\n")), None);
    assert_eq!(previous_branch_name(&probe(0, "refs/tags/v1\n")), None);
    assert_eq!(previous_branch_name(&probe(0, "refs/heads/\n")), None);
    assert_eq!(previous_branch_name(&probe(0, "")), None);
}
