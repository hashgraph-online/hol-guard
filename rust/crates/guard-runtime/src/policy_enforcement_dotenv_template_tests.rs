use super::*;

use super::super::policy_enforcement_facts::payload_facts;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use tempfile::TempDir;

/// The placeholder line a committed template documents its variables with.
#[cfg(unix)]
const TEMPLATE: &str = "TOKEN=replace-me\nSERVICE_URL=http://localhost:4000\n";

/// A repository whose working tree holds the files a case names, with a home
/// folder outside it so the operator's own git configuration cannot reach in.
#[cfg(unix)]
struct Repo {
    root: TempDir,
    home: TempDir,
}

#[cfg(unix)]
impl Repo {
    fn new() -> Self {
        let repo = Self {
            root: tempfile::tempdir().expect("a repository root"),
            home: tempfile::tempdir().expect("a home outside it"),
        };
        repo.git(&["init", "-q", "-b", "main"]);
        repo.write("src/index.ts", "export const route = 2;\n");
        repo.commit("first");
        repo
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn git(&self, arguments: &[&str]) {
        let output = Command::new("git")
            .args(["-c", "commit.gpgsign=false"])
            .args(arguments)
            .current_dir(self.path())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .output()
            .expect("git runs");
        assert!(output.status.success(), "git {arguments:?}: {output:?}");
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.path().join(relative);
        fs::create_dir_all(path.parent().expect("a parent")).expect("a directory for the file");
        fs::write(path, text).expect("the file");
    }

    fn commit(&self, subject: &str) {
        self.git(&["add", "-A", "-f"]);
        self.git(&["commit", "-q", "-m", subject]);
    }

    /// Whether the policy floor still calls a read of `relative` sensitive.
    fn sensitive(&self, relative: &str) -> bool {
        self.sensitive_action(relative, "Read", PreToolActionTypeV1::Harness, true)
    }

    /// Whether the floor calls this repository's `relative` sensitive to a
    /// session whose working directory is `cwd`.
    fn sensitive_from(&self, cwd: &Path, relative: &str) -> bool {
        self.sensitive_named(cwd, &self.path().join(relative))
    }

    /// Whether the floor calls a read of `named`, an absolute path that need
    /// not lie in this repository, sensitive to a session in `cwd`.
    fn sensitive_named(&self, cwd: &Path, named: &Path) -> bool {
        let payload = json!({
            "tool_name": "Read",
            "tool_input": {"file_path": named.to_str().expect("a printable path")},
            "cwd": cwd.to_str().expect("a printable working directory"),
        });
        payload_facts(
            &payload,
            "claude-code",
            PreToolActionTypeV1::Harness,
            true,
            "native_policy_reapproval_required",
            None,
        )
        .expect("a read payload")
        .sensitive_target
    }

    /// Whether the floor calls `relative` sensitive for `tool` and `action`.
    /// `read_request` is what the classified call says about itself: a read
    /// names the file it reads and nothing else.
    fn sensitive_action(
        &self,
        relative: &str,
        tool: &str,
        action: PreToolActionTypeV1,
        read_request: bool,
    ) -> bool {
        let named = self.path().join(relative);
        let payload = json!({
            "tool_name": tool,
            "tool_input": {"file_path": named.to_str().expect("a printable path")},
            "cwd": self.path().to_str().expect("a printable root"),
        });
        payload_facts(
            &payload,
            "claude-code",
            action,
            read_request,
            "native_policy_reapproval_required",
            None,
        )
        .expect("a payload")
        .sensitive_target
    }
}

/// The relief the read gate already grants a committed, placeholder-only
/// template has to reach the policy floor as well, or the floor asks for
/// reapproval on a file the gate just allowed.
#[cfg(unix)]
#[test]
fn a_committed_placeholder_template_clears_the_floor() {
    let repo = Repo::new();
    repo.write(".env.example", TEMPLATE);
    repo.commit("document the variables");
    assert!(!repo.sensitive(".env.example"));
}

/// Nothing proves an untracked template, so the family screen stands.
#[cfg(unix)]
#[test]
fn an_untracked_template_keeps_its_floor() {
    let repo = Repo::new();
    repo.write(".env.example", TEMPLATE);
    assert!(repo.sensitive(".env.example"));
}

/// A template that documents its variables with a live value is a secret
/// whatever the index says about it.
#[cfg(unix)]
#[test]
fn a_committed_template_holding_a_value_keeps_its_floor() {
    let repo = Repo::new();
    repo.write(
        ".env.example",
        "MODEL_GATEWAY=gsk_u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzdocJ2isAjIh\n",
    );
    repo.commit("document the variables");
    assert!(repo.sensitive(".env.example"));
}

/// The template relief is the template's alone: a committed `.env` is the
/// file the family screen exists for.
#[cfg(unix)]
#[test]
fn a_committed_environment_file_keeps_its_floor() {
    let repo = Repo::new();
    repo.write(".env", TEMPLATE);
    repo.commit("add the environment file");
    assert!(repo.sensitive(".env"));
}

/// A template parked inside a credential store keeps that family's floor,
/// because the directories above it are screened as the directories they are.
#[cfg(unix)]
#[test]
fn a_template_inside_a_credential_store_keeps_its_floor() {
    let repo = Repo::new();
    repo.write(".aws/.env.example", TEMPLATE);
    repo.commit("document the variables");
    assert!(repo.sensitive(".aws/.env.example"));
}

/// The relief answers a read. A write of the same committed template would put
/// whatever it writes into the file, so the floor keeps asking there.
#[cfg(unix)]
#[test]
fn a_write_of_a_committed_template_keeps_its_floor() {
    let repo = Repo::new();
    repo.write(".env.example", TEMPLATE);
    repo.commit("document the variables");
    assert!(!repo.sensitive(".env.example"));
    assert!(repo.sensitive_action(
        ".env.example",
        "Write",
        PreToolActionTypeV1::FileWrite,
        false
    ));
    assert!(repo.sensitive_action(
        ".env.example",
        "Edit",
        PreToolActionTypeV1::FileWrite,
        false
    ));
    // A call that writes keeps the floor whatever its action type is. The
    // types that carry MCP calls and the harness's own editing tools carry
    // their reads too, so the operation is what tells them apart.
    for action in [
        PreToolActionTypeV1::McpTool,
        PreToolActionTypeV1::Unknown,
        PreToolActionTypeV1::Harness,
        PreToolActionTypeV1::Command,
    ] {
        assert!(
            repo.sensitive_action(".env.example", "write_file", action, false),
            "a write classified {action:?} keeps the floor"
        );
    }
}

/// Agent work runs from linked worktrees, and a worktree session reading the
/// checkout it was cut from is the same repository seen from the other side.
#[cfg(unix)]
#[test]
fn a_worktree_session_reads_the_template_of_the_checkout_it_was_cut_from() {
    let repo = Repo::new();
    repo.write(".env.example", TEMPLATE);
    repo.commit("document the variables");
    let elsewhere = tempfile::tempdir().expect("a root for the worktree");
    let linked = elsewhere.path().join("review");
    repo.git(&[
        "worktree",
        "add",
        "-q",
        "-b",
        "review",
        linked.to_str().expect("a printable worktree path"),
    ]);
    assert!(!repo.sensitive_from(&linked, ".env.example"));
    // The relief is still the template's alone from that side.
    repo.write(".env", TEMPLATE);
    repo.commit("add the environment file");
    assert!(repo.sensitive_from(&linked, ".env"));
}

/// A link reaches a file under a name of its own. The relief belongs to the
/// name the request wrote as much as to the file behind it, so a link that
/// spells the local dotenv file keeps that family.
#[cfg(unix)]
#[test]
fn a_link_named_after_the_local_dotenv_file_keeps_its_floor() {
    let repo = Repo::new();
    repo.write(".env.example", TEMPLATE);
    repo.commit("document the variables");
    fs::create_dir_all(repo.path().join("config")).expect("a configuration directory");
    std::os::unix::fs::symlink("../.env.example", repo.path().join("config/.env"))
        .expect("a link to the template");
    assert!(!repo.sensitive(".env.example"));
    assert!(repo.sensitive("config/.env"));
}

/// A repository cloned inside a worktree is its own repository. The worktree
/// above it shares the session's git directory, but the nested checkout does
/// not, so its files answer for themselves.
#[cfg(unix)]
#[test]
fn a_template_in_a_repository_nested_inside_a_worktree_keeps_its_floor() {
    let repo = Repo::new();
    repo.write(".env.example", TEMPLATE);
    repo.commit("document the variables");
    let elsewhere = tempfile::tempdir().expect("a root for the worktree");
    let linked = elsewhere.path().join("review");
    repo.git(&[
        "worktree",
        "add",
        "-q",
        "-b",
        "review",
        linked.to_str().expect("a printable worktree path"),
    ]);
    // The worktree's own copy is the session's repository seen from the side.
    assert!(!repo.sensitive_named(repo.path(), &linked.join(".env.example")));

    let nested = linked.join("vendor/storefront");
    fs::create_dir_all(&nested).expect("a directory for the nested checkout");
    fs::write(nested.join(".env.example"), TEMPLATE).expect("the nested template");
    let nested_path = nested.to_str().expect("a printable nested path");
    repo.git(&["init", "-q", "-b", "main", nested_path]);
    repo.git(&["-C", nested_path, "add", "-A", "-f"]);
    assert!(
        repo.sensitive_named(repo.path(), &nested.join(".env.example")),
        "the nested checkout owns the file, not the worktree above it"
    );
}

/// A harness that leaves `cwd` out of its payload still reports the working
/// directory on the hook envelope, and the read gate resolves a relative path
/// against that one. The relief is proven against the same directory.
#[cfg(unix)]
#[test]
fn a_relative_template_resolves_against_the_hook_working_directory() {
    let repo = Repo::new();
    repo.write(".env.example", TEMPLATE);
    repo.commit("template");
    let payload = json!({
        "tool_name": "Read",
        "tool_input": {"file_path": ".env.example"},
    });
    let sensitive = |cwd: Option<&str>| {
        payload_facts(
            &payload,
            "claude-code",
            PreToolActionTypeV1::Harness,
            true,
            "native_policy_reapproval_required",
            cwd,
        )
        .expect("a read payload")
        .sensitive_target
    };
    let root = repo.path().to_str().expect("a printable root");
    assert!(!sensitive(Some(root)));
    assert!(
        sensitive(None),
        "without a working directory nothing proves the template"
    );
}
