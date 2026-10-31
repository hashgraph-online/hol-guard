use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

const FLOOR: &str = "native_git_execution_context_review";
const CONTAINED: &str = "native_workspace_containment_required";

fn git(repository: &std::path::Path, home: &std::path::Path, arguments: &[&str]) {
    let mut command = std::process::Command::new("git");
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_COMMON_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_NAMESPACE",
    ] {
        command.env_remove(name);
    }
    let status = command
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .status()
        .unwrap();
    assert!(status.success(), "git {arguments:?}");
}

fn reason(home: &std::path::Path, cwd: &std::path::Path, command: &str) -> String {
    let controls = github_controls("enabled");
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .reason_code
}

// Agents look around before they read history. A read-only listing writes no
// configuration, so it cannot change what the later Git read runs.
#[test]
fn read_only_segments_before_a_git_read_keep_its_proof() {
    let root = std::env::temp_dir().join(format!("guard read sequence {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    let outside = root.join("outside");
    for directory in [&home, &repository, &outside] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = home.canonicalize().unwrap();
    let repository = repository.canonicalize().unwrap();
    let outside = outside.canonicalize().unwrap();
    git(&repository, &home, &["init", "--quiet"]);
    git(
        &repository,
        &home,
        &["config", "user.email", "fixture@example.test"],
    );
    git(&repository, &home, &["config", "user.name", "fixture"]);
    std::fs::write(repository.join("package.json"), "{}\n").unwrap();
    git(&repository, &home, &["add", "-A"]);
    git(&repository, &home, &["commit", "--quiet", "-m", "fixture"]);

    for command in [
        "ls && cat package.json 2>/dev/null; git log --oneline -5",
        "ls -la && git status --short",
        "pwd && git diff --stat",
        // A glob pathspec keeps its own read review but writes nothing, so a
        // later read in the same command keeps its configuration proof.
        "git log --oneline HEAD --name-only -- 'src/db/*' '*migration*' 2>/dev/null | head -30; \
         git merge-base --is-ancestor HEAD HEAD 2>/dev/null && echo merged || echo not",
    ] {
        assert_ne!(reason(&home, &repository, command), FLOOR, "{command}");
    }
    // No repository: Git stops during setup and runs nothing.
    for command in ["git status", "git status 2>&1; ls -a"] {
        assert_ne!(reason(&home, &outside, command), FLOOR, "{command}");
    }

    // The configuration probe still sees a pager the read would launch.
    let marker = root.join("pager-ran").to_string_lossy().replace('\\', "/");
    git(
        &repository,
        &home,
        &["config", "core.pager", &format!("touch '{marker}'")],
    );
    // Either Git context check may stop it first; both keep the review. On
    // macOS the helper check sends a Git inspection to its read-only
    // sandbox instead (`git_inspections_require_protected_execution_not_helper_consent`),
    // which still never runs it directly.
    let contained = cfg!(target_os = "macos").then_some("native_git_readonly_containment_required");
    for command in ["git log --oneline -5", "ls && git log --oneline -5"] {
        let code = reason(&home, &repository, command);
        assert!(
            [FLOOR, "native_git_helper_context_review"].contains(&code.as_str())
                || contained == Some(code.as_str()),
            "{command}: {code}"
        );
        assert_ne!(action(&home, &repository, command), "allow", "{command}");
    }
}

fn action(home: &std::path::Path, cwd: &std::path::Path, command: &str) -> String {
    let controls = github_controls("enabled");
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

// Agents read the commit two branches share with `git merge-base A B | xargs
// git log`. merge-base prints only object names, so the child is a Git read
// with an object name appended, and the configuration probe sees it as one.
#[test]
fn merge_base_object_names_feed_a_git_read() {
    let root = std::env::temp_dir().join(format!("guard xargs read {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    for directory in [&home, &repository] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = home.canonicalize().unwrap();
    let repository = repository.canonicalize().unwrap();
    git(&repository, &home, &["init", "--quiet"]);
    git(
        &repository,
        &home,
        &["config", "user.email", "fixture@example.test"],
    );
    git(&repository, &home, &["config", "user.name", "fixture"]);
    std::fs::write(repository.join("package.json"), "{}\n").unwrap();
    git(&repository, &home, &["add", "-A"]);
    git(&repository, &home, &["commit", "--quiet", "-m", "fixture"]);
    git(&repository, &home, &["branch", "feature"]);

    for command in [
        "git merge-base feature HEAD | xargs git log --format='%H %ci %s' -1",
        "git merge-base feature HEAD | xargs -r git show --stat",
        "git merge-base --is-ancestor feature HEAD && echo merged || echo not; echo ---; \
         git log --format=\"%H %ci %s\" -1 feature; echo ---base---; \
         git merge-base feature HEAD | xargs git log --format=\"%H %ci %s\" -1",
    ] {
        assert_eq!(action(&home, &repository, command), "allow", "{command}");
    }
    for command in [
        // Children that write, run helpers or reach the network.
        "git merge-base feature HEAD | xargs git log --output=out.txt -1",
        "git merge-base feature HEAD | xargs git diff --ext-diff",
        "git merge-base feature HEAD | xargs git -c core.pager=x log -1",
        "git merge-base feature HEAD | xargs git push origin",
        "git merge-base feature HEAD | xargs git checkout",
        "git merge-base feature HEAD | xargs git reset --hard",
        "git merge-base feature HEAD | xargs git branch -D",
        // Substitution and a child named by its input.
        "git merge-base feature HEAD | xargs -I{} git log {}",
        "git merge-base feature HEAD | xargs -I{} {} log",
        "git merge-base feature HEAD | xargs sh -c 'git log \"$@\"' _",
        // Producers that can print words other than object names.
        "git rev-parse HEAD | xargs git log",
        "echo --output=out.txt | xargs git log",
        "git log --format=%s -1 | xargs git log",
        "git merge-base \"$(cat ref)\" HEAD | xargs git log",
        "git merge-base feature HEAD | tr a b | xargs git log",
    ] {
        assert_ne!(action(&home, &repository, command), "allow", "{command}");
    }

    // The probe still sees a pager or diff helper the child would launch.
    let marker = root.join("helper-ran").to_string_lossy().replace('\\', "/");
    git(
        &repository,
        &home,
        &["config", "diff.external", &format!("touch '{marker}'")],
    );
    let command = "git merge-base feature HEAD | xargs git show";
    assert_ne!(action(&home, &repository, command), "allow", "{command}");
    assert!(!root.join("helper-ran").exists());
}

fn result(
    home: &std::path::Path,
    cwd: &std::path::Path,
    command: &str,
) -> guard_contracts::PreToolResultV1 {
    let controls = github_controls("enabled");
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash", "tool_input":{"command":command}}),
        Some(&controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
}

// An agent told only that "this Git read may execute a configured helper"
// stopped using Git for the rest of the task. When the read itself was proven
// helper-free and only an earlier step kept that proof from carrying over,
// the reason names the step and says the read is fine as its own command.
#[test]
fn an_unproven_step_before_a_proven_git_read_is_named() {
    let root = std::env::temp_dir().join(format!("guard read order {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    for directory in [&home, &repository] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = home.canonicalize().unwrap();
    let repository = repository.canonicalize().unwrap();
    git(&repository, &home, &["init", "--quiet"]);
    git(
        &repository,
        &home,
        &["config", "user.email", "fixture@example.test"],
    );
    git(&repository, &home, &["config", "user.name", "fixture"]);
    std::fs::write(repository.join("package.json"), "{}\n").unwrap();
    git(&repository, &home, &["add", "-A"]);
    git(&repository, &home, &["commit", "--quiet", "-m", "fixture"]);
    let linked = root.join("linked");
    git(
        &repository,
        &home,
        &["worktree", "add", "--quiet", linked.to_str().unwrap()],
    );
    let linked = linked.canonicalize().unwrap();

    let command = "corepack pnpm --version && git status --short";
    let ordered = result(&home, &linked, command);
    // macOS always has the workspace sandbox; Linux has it when the bwrap
    // overlay probe succeeds. With it, Git in a linked worktree runs there,
    // so the whole chain runs contained and raises no review to word.
    // Elsewhere, Windows included, the review names the step.
    let sandboxed_linux = cfg!(target_os = "linux") && ordered.reason_code == CONTAINED;
    if cfg!(target_os = "macos") || sandboxed_linux {
        assert_eq!(ordered.reason_code, CONTAINED, "{}", ordered.reason);
        assert_eq!(ordered.minimum_action, "sandbox-required", "{command}");
    } else {
        assert_eq!(ordered.reason_code, FLOOR, "{}", ordered.reason);
        assert!(
            ordered
                .reason
                .contains("Step 1 (corepack pnpm) runs before the Git read")
                && ordered.reason.contains("run it as its own command"),
            "{}",
            ordered.reason
        );
    }
    assert_ne!(reason(&home, &linked, "git status --short"), FLOOR);

    // A read that would launch a pager keeps the generic reason: running it
    // alone would not help.
    let marker = root.join("pager-ran").to_string_lossy().replace('\\', "/");
    git(
        &repository,
        &home,
        &["config", "core.pager", &format!("touch '{marker}'")],
    );
    let helper = result(&home, &linked, "corepack pnpm --version && git log -1");
    assert!(
        !helper.reason.contains("own command"),
        "{}: {}",
        helper.reason_code,
        helper.reason
    );
}

// Agents name commits with Git's brace suffixes, as in
// `git rev-parse <sha>^{commit}`. A brace with no comma is literal text to the
// shell, so the read keeps its proof. A brace that spells a sensitive name,
// or a `..` sequence that bash expands, still does not.
#[test]
fn git_brace_revision_suffixes_are_not_globs() {
    let root = std::env::temp_dir().join(format!("guard brace revision {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    for directory in [&home, &repository] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = home.canonicalize().unwrap();
    let repository = repository.canonicalize().unwrap();
    git(&repository, &home, &["init", "--quiet"]);
    git(
        &repository,
        &home,
        &["config", "user.email", "fixture@example.test"],
    );
    git(&repository, &home, &["config", "user.name", "fixture"]);
    std::fs::write(repository.join("package.json"), "{}\n").unwrap();
    git(&repository, &home, &["add", "-A"]);
    git(&repository, &home, &["commit", "--quiet", "-m", "fixture"]);

    for command in [
        "git rev-parse HEAD^{commit}",
        "git rev-parse --verify 'HEAD^{tree}'",
        "git rev-parse HEAD@{0}",
        "git log -1 HEAD^{commit}",
        "git status --short && git rev-parse HEAD^{commit} && git show -s --format='%H %s' HEAD && git worktree list",
    ] {
        assert_eq!(action(&home, &repository, command), "allow", "{command}");
    }
    // A brace with `..` is a sequence: bash expands `.en{v..v}` to `.env`.
    std::fs::write(repository.join(".env"), "FIXTURE=1\n").unwrap();
    std::fs::write(repository.join(".npmrc"), "fixture=1\n").unwrap();
    std::fs::create_dir_all(repository.join(".ssh")).unwrap();
    for command in [
        "cat .en{v..v}",
        "cat .npmr{c..c}",
        "cat .git-credential{s..s}",
        "cat .en{v..v..1}",
        "grep -r x .ss{h..h}",
        "git log -1 -- '{.env}'",
        "git log -1 -- 'config/{.env,x}'",
        "git diff HEAD -- '{.env,README.md}'",
    ] {
        assert_ne!(action(&home, &repository, command), "allow", "{command}");
    }
}

// An explicit Git Allow settles Rust's review of an unproven read, but a glob
// that bash or a Git pathspec could expand to a secret file name keeps the
// review: `.en?` is `.env` once the shell expands it.
#[test]
fn an_explicit_git_allow_does_not_settle_a_glob_that_names_a_secret() {
    let root = std::env::temp_dir().join(format!("guard allow secret glob {}", std::process::id()));
    let _cleanup = FixtureCleanup(root.clone());
    let home = root.join("home");
    let repository = root.join("repository");
    for directory in [&home, &repository] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let home = home.canonicalize().unwrap();
    let repository = repository.canonicalize().unwrap();
    git(&repository, &home, &["init", "--quiet"]);
    git(
        &repository,
        &home,
        &["config", "user.email", "fixture@example.test"],
    );
    git(&repository, &home, &["config", "user.name", "fixture"]);
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join("src/index.ts"), "export {};\n").unwrap();
    std::fs::write(repository.join("README.md"), "fixture\n").unwrap();
    git(&repository, &home, &["add", "-A"]);
    git(&repository, &home, &["commit", "--quiet", "-m", "fixture"]);
    std::fs::write(repository.join(".env"), "FIXTURE=1\n").unwrap();

    for command in [
        "git diff --no-index .en? README.md",
        "git diff --no-index .en{v..v} README.md",
        "git diff --no-index .e*v README.md",
        "git log -p -1 -- .en?",
        "git log -p -1 -- '.en*'",
        "git show HEAD -- '*.env*'",
        "git log -p -1 -- ':(top).en*'",
        "git log -p -1 -- ':(top,glob).en*'",
        "git log -p -1 -- ':/!.en?'",
    ] {
        assert_ne!(action(&home, &repository, command), "allow", "{command}");
    }
    // An ordinary glob and a brace revision keep the Allow.
    for command in [
        "git diff --no-index src/inde? README.md",
        "git log -p -1 -- 'src/*.ts'",
        "git log -1 HEAD@{0}",
    ] {
        assert_eq!(action(&home, &repository, command), "allow", "{command}");
    }
}
