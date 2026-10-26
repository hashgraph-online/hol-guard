#![cfg(unix)]

//! `cd <sibling>; ...` and `cd <sibling> && ...; ...` sequences, `awk` reads
//! of sibling files and `rustfmt` of sibling sources. After `cd <dir>;` every
//! later segment runs in `<dir>` when the `cd` succeeded and in the original
//! directory when it failed, so each one must be safe in both. Steps chained
//! to the `cd` with `&&` or `|` run in `<dir>` only; a `||` alternative and
//! everything after it run in either directory, like a `;` tail.

use crate::git_helper_fixture as fixture;
use fixture::*;
use guard_command::pretool::{evaluate_pre_tool_envelope_with_execution_context, PathContext};
use serde_json::json;
use std::path::{Path, PathBuf};

struct Space {
    home: PathBuf,
    project: PathBuf,
    sibling: PathBuf,
}

fn git(directory: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .env("HOME", std::env::temp_dir())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn space(label: &str) -> (Space, FixtureCleanup) {
    // Stay out of the system temporary root so no ancestor carries a
    // toolchain file or a protected prefix of its own.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-sibling-sequences")
        .join(format!("{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    let project = home.join("code/app-portal");
    let sibling = home.join("code/service-api");
    for repository in [&project, &sibling] {
        std::fs::create_dir_all(repository).unwrap();
        git(repository, &["init", "--quiet"]);
    }
    write(&sibling.join("README.md"), "# service-api\n");
    write(&sibling.join("src/index.ts"), "export {};\n");
    write(
        &sibling.join("src/lib.rs"),
        "pub fn name() -> &'static str {\n    \"fixture\"\n}\n",
    );
    write(&sibling.join("src/main.rs"), "mod child;\nfn main() {}\n");
    write(&sibling.join("src/child.rs"), "pub fn child() {}\n");
    write(
        &sibling.join(".github/workflows/check.rs"),
        "fn main() {}\n",
    );
    write(&sibling.join(".cache/lib.rs"), "fn main() {}\n");
    write(&sibling.join(".env"), "SYNTHETIC_ONLY=fixture\n");
    write(&home.join(".ssh/id_rsa"), "synthetic fixture\n");
    write(&home.join(".aws/credentials"), "[default]\n");
    write(
        &home.join(".rustup/settings.toml"),
        "version = \"12\"\ndefault_toolchain = \"stable\"\n",
    );
    (
        Space {
            home,
            project,
            sibling,
        },
        FixtureCleanup(root),
    )
}

fn decide(space: &Space, harness: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        space.home.to_str(),
        space.project.to_str(),
    )
}

/// Rustfmt proofs read the stamped hook environment. Without one they fall
/// back to the test process's own, which a rustup-run `cargo test` fills with
/// `RUSTUP_TOOLCHAIN` and `RUSTUP_HOME`.
fn decide_stamped(space: &Space, harness: &str, command: &str) -> guard_contracts::PreToolResultV1 {
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: std::env::var("PATH").unwrap(),
        environment_names: Vec::new(),
        environment_digest: "0".repeat(64),
        home: space.home.to_str().map(str::to_owned),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    };
    evaluate_pre_tool_envelope_with_execution_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
        None,
        None,
        PathContext {
            home_dir: space.home.to_str(),
            cwd: space.project.to_str(),
            ..PathContext::default()
        },
        Some(&environment),
    )
}

fn check(space: &Space, allowed: &[String], reviewed: &[String]) {
    check_with(decide, space, allowed, reviewed);
}

fn check_with(
    decide: fn(&Space, &str, &str) -> guard_contracts::PreToolResultV1,
    space: &Space,
    allowed: &[String],
    reviewed: &[String],
) {
    for harness in ["codex", "claude-code"] {
        for command in allowed {
            let result = decide(space, harness, command);
            assert_eq!(
                result.decision, "allow",
                "{harness} `{command}`: {}",
                result.reason_code
            );
        }
        for command in reviewed {
            let result = decide(space, harness, command);
            assert_ne!(result.decision, "allow", "{harness} `{command}`");
        }
    }
}

#[test]
fn semicolon_cd_runs_later_reads_in_either_directory() {
    let (space, _cleanup) = space("cd");
    let sibling = space.sibling.display();
    let parent = space.project.parent().unwrap().display();
    let ssh = space.home.join(".ssh");
    let ssh = ssh.display();
    check(
        &space,
        &[
            format!("cd {sibling} 2>/dev/null; true"),
            format!("cd {sibling}; ls"),
            format!("cd {sibling}; ls src && pwd"),
            format!("cd {sibling}; git status"),
            format!("cd {parent}; true"),
            // `git log` can start a configured diff helper, and the helper
            // probe inspects both directories this read can run in.
            format!("cd {sibling}; git log -1"),
        ],
        &[
            format!("cd {ssh}; cat id_rsa"),
            format!("cd {sibling}; cat .env"),
            format!("cd {sibling}; rm -rf src"),
        ],
    );
}

#[test]
fn semicolon_cd_git_reads_need_helper_free_configuration_in_both_directories() {
    let (space, _cleanup) = space("cd-git");
    let command = format!("cd {}; git status", space.sibling.display());
    git(
        &space.sibling,
        &["config", "core.fsmonitor", "./synthetic-never-execute"],
    );
    check(&space, &[], std::slice::from_ref(&command));
    git(&space.sibling, &["config", "--unset", "core.fsmonitor"]);
    check(&space, std::slice::from_ref(&command), &[]);
    // A failed `cd` leaves the read in the original directory.
    git(
        &space.project,
        &["config", "core.fsmonitor", "./synthetic-never-execute"],
    );
    check(&space, &[], std::slice::from_ref(&command));
}

#[test]
fn and_cd_reads_then_semicolon_reads_run_where_the_shell_runs_them() {
    let (space, _cleanup) = space("and-cd");
    let sibling = space.sibling.display();
    check(
        &space,
        &[
            format!(
                "cd {sibling} && git status --short | rg '^UU|^AA' | head -30; \
                 git status --short | rg -c '^UU'"
            ),
            format!("cd {sibling} && git status --short && ls src; git status"),
            format!("cd {sibling} && ls src; ls"),
            // `git log` can start a configured diff helper, and the helper
            // probe inspects both directories this list can run its reads in.
            format!("cd {sibling} && git log -1; git status"),
        ],
        &[
            // `||` runs its right side in the original directory when the
            // `cd` fails, and the tail runs in either directory.
            format!("cd {sibling} && git status || rm -rf src; git status"),
            format!("cd {sibling} && git status; rm -rf src"),
            format!("cd {sibling} && git status; cat .env"),
            format!("cd {sibling} && git status; cd src; git status"),
            format!("cd {sibling} && git config core.pager id; git status"),
        ],
    );
}

#[test]
fn and_cd_git_reads_need_helper_free_configuration_where_they_run() {
    let (space, _cleanup) = space("and-cd-git");
    let command = format!(
        "cd {} && git status --short; git status --short",
        space.sibling.display()
    );
    check(&space, std::slice::from_ref(&command), &[]);
    // The head runs in the sibling; a failed `cd` leaves the tail in the
    // original directory.
    for repository in [&space.sibling, &space.project] {
        git(
            repository,
            &["config", "core.fsmonitor", "./synthetic-never-execute"],
        );
        check(&space, &[], std::slice::from_ref(&command));
        git(repository, &["config", "--unset", "core.fsmonitor"]);
    }
    check(&space, std::slice::from_ref(&command), &[]);
}

#[test]
fn and_cd_reads_with_or_fallbacks_run_where_the_shell_runs_them() {
    let (space, _cleanup) = space("or-cd");
    let sibling = space.sibling.display();
    check(
        &space,
        &[
            format!(
                r#"cd {sibling} && git status --short | head -4 && git worktree list | grep -c "fix" || echo "no fix worktrees remain" && gh pr list --repo example-org/app-portal --state open --author octocat --json number,title --jq '.[] | "\(.number) \(.title)"' | head -4"#
            ),
            format!("cd {sibling} && ls src || echo missing"),
            format!("cd {sibling} && git status --short || echo none; git worktree list"),
            format!("cd {sibling} && ls || echo none && git log -1"),
        ],
        &[
            // A failed `cd` runs the alternative and everything after it in
            // the original directory; each must be safe in both.
            format!("cd {sibling} && git status || cat .env"),
            format!("cd {sibling} && ls || echo none && rm -rf src"),
            format!("cd {sibling} && ls || git push"),
            format!("cd {sibling} && ls || cd src && git status"),
            format!("cd {sibling} && ls || gh pr merge 1 --repo example-org/app-portal"),
        ],
    );
}

#[test]
fn or_fallback_git_reads_need_helper_free_configuration_in_both_directories() {
    let (space, _cleanup) = space("or-cd-git");
    let command = format!(
        "cd {} && ls src || git status --short",
        space.sibling.display()
    );
    check(&space, std::slice::from_ref(&command), &[]);
    for repository in [&space.sibling, &space.project] {
        git(
            repository,
            &["config", "core.fsmonitor", "./synthetic-never-execute"],
        );
        check(&space, &[], std::slice::from_ref(&command));
        git(repository, &["config", "--unset", "core.fsmonitor"]);
    }
}

#[test]
fn awk_reads_sibling_files_like_cat() {
    let (space, _cleanup) = space("awk");
    let sibling = space.sibling.display();
    let home = space.home.display();
    check(
        &space,
        &[
            format!("awk '{{print FNR}}' {sibling}/README.md"),
            format!(
                "awk 'length > 100 {{print FILENAME\":\"FNR\": \"length}}' \
                 {sibling}/src/index.ts {sibling}/README.md"
            ),
            format!("awk -F: -v limit=3 'NR <= limit {{print $1}}' {sibling}/README.md"),
            format!("cat {sibling}/README.md | awk '{{print $1}}'"),
        ],
        &[
            format!("awk 'BEGIN {{ system(\"id\") }}' {sibling}/README.md"),
            format!("awk '{{ \"date\" | getline now; print now }}' {sibling}/README.md"),
            format!("awk '{{print > \"copy.txt\"}}' {sibling}/README.md"),
            format!("awk '{{print | \"sh\"}}' {sibling}/README.md"),
            format!("awk '{{print}}' {home}/.aws/credentials"),
            format!("awk '{{print}}' {home}/.ssh/id_rsa"),
            format!("awk '{{print}}' {sibling}/.env"),
            format!("awk -f {sibling}/README.md {sibling}/README.md"),
            format!("awk '{{print}}' limit=1 {sibling}/README.md"),
        ],
    );
}

#[test]
fn rustfmt_rewrites_sibling_sources_that_pass_the_write_proof() {
    let (space, _cleanup) = space("rustfmt");
    let sibling = space.sibling.display();
    let allowed = format!("rustfmt --edition 2021 {sibling}/src/lib.rs");
    // A real file named like a toolchain selector must not make it a target.
    write(&space.project.join("+fmt.rs"), "pub fn f() {}\n");
    check_with(
        decide_stamped,
        &space,
        &[
            allowed.clone(),
            format!("rustfmt --check --edition=2021 {sibling}/src/lib.rs"),
        ],
        &[
            // A child module would be rewritten without its own proof.
            format!("rustfmt --edition 2021 {sibling}/src/main.rs"),
            format!("rustfmt --edition 2021 {sibling}/.github/workflows/check.rs"),
            format!("rustfmt --edition 2021 {sibling}/.cache/lib.rs"),
            format!("rustfmt --edition 2021 {sibling}/README.md"),
            format!("rustfmt --config-path {sibling} {sibling}/src/lib.rs"),
            format!("rustfmt +nightly {sibling}/src/lib.rs"),
            format!("rustfmt +fmt.rs {sibling}/src/lib.rs"),
            format!("rustfmt {sibling}/src/lib.rs +fmt.rs"),
            format!("rustfmt --edition 2021 {sibling}/src/lib.rs && ls"),
        ],
    );
    // A missing rustup default or a linked custom default cannot authorize a
    // potentially executable formatter, even when its target is bounded.
    let rustup_settings = space.home.join(".rustup/settings.toml");
    std::fs::remove_file(&rustup_settings).unwrap();
    check_with(decide_stamped, &space, &[], &[allowed.clone()]);
    write(
        &rustup_settings,
        "default_toolchain = \"custom-formatter\"\n",
    );
    check_with(decide_stamped, &space, &[], &[allowed.clone()]);
    write(&rustup_settings, "default_toolchain = \"stable\"\n");
    check_with(decide_stamped, &space, &[allowed.clone()], &[]);

    // The rustup proxy reads the toolchain file above the working directory;
    // a `path` entry there selects another binary.
    write(
        &space.project.join("rust-toolchain.toml"),
        "[toolchain]\npath = \"/opt/synthetic-toolchain\"\n",
    );
    check_with(decide_stamped, &space, &[], &[allowed]);
}
