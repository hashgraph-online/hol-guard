use crate::git_helper_fixture as fixture;
use fixture::*;
use serde_json::json;

const FLOOR: &str = "native_git_execution_context_review";

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
    // Either Git context check may stop it first; both keep the review.
    for command in ["git log --oneline -5", "ls && git log --oneline -5"] {
        let code = reason(&home, &repository, command);
        assert!(
            [FLOOR, "native_git_helper_context_review"].contains(&code.as_str()),
            "{command}: {code}"
        );
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
    assert_eq!(ordered.reason_code, FLOOR, "{}", ordered.reason);
    assert!(
        ordered
            .reason
            .contains("Step 1 (corepack pnpm) runs before the Git read")
            && ordered.reason.contains("run it as its own command"),
        "{}",
        ordered.reason
    );
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
