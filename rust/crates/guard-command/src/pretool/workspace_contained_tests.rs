use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use guard_contracts::NativeCommandControlBindingV1;
use std::path::{Path, PathBuf};

pub(super) fn controls() -> CompiledNativeCommandControls {
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected",
        "revision": 1, "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::new(&binding).unwrap()
}

pub(super) fn workspace(name: &str, git: bool) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-ws-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("package.json"), "{}").unwrap();
    if git {
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    }
    root.canonicalize().unwrap()
}

pub(super) fn reason(harness: &str, command: &str, cwd: &Path, with_controls: bool) -> String {
    let controls = controls();
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        with_controls.then_some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    )
    .reason_code
}

pub(super) const CONTAINED: &str = "native_workspace_containment_required";

#[test]
fn unproven_local_commands_run_in_the_workspace_sandbox_on_macos() {
    let ws = workspace("convert", true);
    for command in [
        "./todo.py add x",
        "python3 app.py",
        "git add -A && git commit -m x",
        "git commit -m init",
        "npm run build && git diff",
        "rm -rf dist node_modules",
        "rm -rf ./build/ && npm run build",
        "rm -f *.pyc",
        "rm notes.txt",
        "chmod +x scripts/run.sh",
        "chmod 755 bin/tool && ./bin/tool",
        // A job specification stops only what this command started.
        "kill %1",
        "kill -9 %1",
        "kill -s TERM %vite",
        "kill -SIGTERM %1",
        "kill -- %1",
        "kill %+ %-",
        "rm -f init_repo.py",
        "rm a.py && rm -rf __pycache__",
        "echo hi > scratch.txt && rm scratch.txt",
        "rmdir node_modules/zod-dir",
        "rm -d build",
        "yarn build",
        "pnpm run test:unit",
        // These Git forms keep every uncommitted change reachable.
        "git switch -c feature/login-form",
        "git checkout -b fix-1",
        "git stash",
        "git stash push -m 'wip: parser'",
        "git stash -u && git switch -c spike",
    ] {
        let got = reason("omp", command, &ws, true);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
}

/// On macOS, narrower node profiles claim these commands before the general
/// workspace profile; each is at least as tightly bounded, or needs no sandbox
/// at all. Linux has only the workspace sandbox.
#[test]
fn node_commands_with_a_narrower_profile_keep_it_on_macos() {
    let ws = workspace("node-narrow", true);
    // The narrow profiles run only these script bodies, from local entrypoints.
    let scripts = r#"{"scripts":{"lint":"eslint src","build":"vite build"}}"#;
    std::fs::write(ws.join("package.json"), scripts).unwrap();
    for entry in ["eslint/bin/eslint.js", "vite/bin/vite.js"] {
        let entry = ws.join("node_modules").join(entry);
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(entry, "").unwrap();
    }
    for (command, narrower) in [
        (
            "npm run lint",
            "native_node_tool_readonly_containment_required",
        ),
        (
            "bun run build",
            "native_node_build_output_containment_required",
        ),
        (
            "/Users/nobody/.nvm/versions/node/v25.2.1/bin/npm run build",
            "native_node_build_output_containment_required",
        ),
        ("npm -v", "native_exact_safe_command"),
    ] {
        let got = reason("omp", command, &ws, true);
        if cfg!(target_os = "macos") {
            assert_eq!(got, narrower, "{command}");
        } else if host() {
            // Linux has no narrower node profile; the workspace sandbox
            // bounds the command instead.
            assert!(got == narrower || got == CONTAINED, "{command}: {got}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
}

/// Inline `node -e` has its own, narrower read-only containment profile, which
/// runs before the general workspace profile and bounds the command at least
/// as tightly.
#[test]
fn inline_node_eval_keeps_its_read_only_containment_profile() {
    let ws = workspace("node-eval", true);
    let got = reason("omp", "node -e 1", &ws, true);
    if cfg!(target_os = "macos") {
        assert_eq!(got, "native_node_eval_readonly_containment_required");
    } else if !host() {
        assert_ne!(got, CONTAINED);
    }
}

#[test]
fn git_init_converts_only_in_a_fresh_workspace() {
    let fresh = workspace("init", false);
    let existing = workspace("init-existing", true);
    let expected = host();
    assert_eq!(
        reason("omp", "git init", &fresh, true) == CONTAINED,
        expected
    );
    assert_eq!(
        reason("omp", "git init && git add -A", &fresh, true) == CONTAINED,
        expected
    );
    assert_ne!(reason("omp", "git init", &existing, true), CONTAINED);
    assert_ne!(reason("omp", "git init sub", &fresh, true), CONTAINED);
    // Earlier work may precede the init when only `&&` joins them.
    assert_eq!(
        reason(
            "omp",
            "mkdir src && git init -b main && git add -A",
            &fresh,
            true
        ) == CONTAINED,
        expected
    );
    for command in [
        // A prefix runs in its own shell, so shell state cannot carry over.
        "cd src && git init",
        "export NAME=x && git init",
        "true || git init",
        "true; git init",
        "true | git init",
        "git init && mkdir src && git init",
    ] {
        assert_ne!(reason("omp", command, &fresh, true), CONTAINED, "{command}");
    }
}

#[test]
fn commands_with_network_privilege_or_escape_stay_at_review() {
    let ws = workspace("reject", true);
    for command in [
        "git push origin main",
        "git fetch origin",
        "gh pr list",
        "curl https://example.com",
        "wget -O out.html https://example.com && git add -A",
        "ssh host ls",
        "find . -delete",
        "FOO=bar rm notes.txt",
        "npm install",
        "sudo ls",
        "chmod 777 x",
        "chmod u+s x",
        "chmod -R 755 .",
        "kill 4821",
        "kill -9 -1",
        "kill %1 4821",
        "kill -l",
        "kill %$name",
        // Only the first word is a signal: every `-N` after it is a pid or a
        // process group, and both reach past this shell's own jobs.
        "kill -9 -1 %1",
        "kill -9 -4821 %1",
        "kill -s TERM -1 %1",
        "kill -- -1 %1",
        "echo $(x)",
        "echo hi > ../out",
        "git reset --hard",
        "git checkout main",
        "git checkout -- src/app.py",
        "git checkout -b fix origin/main",
        "git switch -c fix origin/main",
        "git switch -C fix",
        "git switch --discard-changes main",
        "git -C ../other switch -c fix",
        "git stash pop",
        "git stash drop",
        "git stash clear",
        "git stash push -- src/app.py",
        "git stash -m",
        "cat .env",
        "GIT_DIR=/x git status",
        "git push --force origin main",
        "git push origin --delete feature",
        "rm -rf .",
        "rm -rf *",
        "rm -rf ./*",
        "rm -rf [a-z]*",
        "rm -rf {*,.*}",
        "rm -rf src/..",
        "rm -rf ~",
        "rm -rf $HOME",
        "rm -r ..",
        "rm ~/notes.txt",
        "yarn",
        "yarn --frozen-lockfile",
        "yarn --immutable",
        "npm --prefix web install",
        "bun a zod",
        "yarn upgrade-interactive",
        "npm i zod",
        "npm isntall zod",
        "npm install-test",
        "yarn add zod",
        "yarn workspace web add zod",
        "pnpm dlx create-vite",
        "npm exec foo",
        "npx foo",
        "bun x foo",
        "npm init vite",
        "npm publish",
        "npm run build && npm install zod",
        "pip install requests",
        "cargo build",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
}

#[test]
fn missing_evidence_keeps_the_command_at_review() {
    let ws = workspace("evidence", true);
    assert_ne!(reason("omp", "./todo.py add x", &ws, false), CONTAINED);
    assert_ne!(reason("cursor", "./todo.py add x", &ws, true), CONTAINED);
    assert_ne!(
        reason("omp", "./todo.py add x", &PathBuf::from("/"), true),
        CONTAINED
    );
    assert_ne!(
        reason(
            "omp",
            "./todo.py add x",
            &PathBuf::from("/private/tmp"),
            true
        ),
        CONTAINED
    );
}

#[test]
fn hostile_git_configuration_stays_at_review() {
    let ws = workspace("hostile", true);
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\thooksPath = /outside/hooks\n",
    )
    .unwrap();
    assert_ne!(reason("omp", "./todo.py add x", &ws, true), CONTAINED);
    std::fs::write(
        ws.join(".git/config"),
        "[include]\n\tpath = ../.gitconfig\n",
    )
    .unwrap();
    assert_ne!(reason("omp", "./todo.py add x", &ws, true), CONTAINED);
    std::fs::write(
        ws.join(".git/config"),
        "[core]\n\tfsmonitor = ./tools/mon\n",
    )
    .unwrap();
    let got = reason("omp", "./todo.py add x", &ws, true);
    assert_eq!(got == CONTAINED, host());
}

#[test]
fn compound_commands_with_literal_redirects_run_in_the_workspace_sandbox() {
    let ws = workspace("redirects", true);
    for command in [
        "printf 'node_modules\\n' > .gitignore && git add -A && git commit -m init",
        "cat > todo.py <<'EOF'\nprint('todo')\nEOF\npython3 todo.py list",
        "python3 app.py > out.txt 2>&1",
        "python3 app.py > out.txt 2>&1; cat out.txt",
        "npm run build > build.log 2>&1 && git add -A",
        // A commit message is not `git init`.
        "echo x > notes.txt && git add -A && git commit -m init",
        // The bounded projection declines hidden targets other than
        // project config files such as `.gitignore`; the sandbox bounds them.
        "printf 'lts\\n' > .tool-versions",
    ] {
        let got = reason("omp", command, &ws, true);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
    let fresh = workspace("redirects-init", false);
    assert_eq!(
        reason(
            "omp",
            "git init && printf 'x\\n' > .gitignore && git add -A",
            &fresh,
            true
        ) == CONTAINED,
        host()
    );
}

#[test]
fn redirects_the_sandbox_cannot_bound_stay_out_of_the_workspace_sandbox() {
    let ws = workspace("redirects-out", true);
    for command in [
        "python3 app.py > ~/out.txt && git add -A",
        "python3 app.py > $OUT && git add -A",
        "python3 app.py > >(tee out.txt) && git add -A",
        "python3 app.py 3> out.txt && git add -A",
        "python3 <<'EOF'\nprint(1)\nEOF\ngit add -A",
        "cat > f.py <<EOF\n$(cat ~/.ssh/id_rsa)\nEOF\ngit add -A",
        "cat ~/.ssh/id_rsa > key.txt && git add -A",
        "git reset --hard > log.txt && git add -A",
        "echo $(curl https://example.com) > page.html && git add -A",
        "cat ~/.ssh/id_rsa > .key",
        "printf x > ~/.zshrc",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    // Without the extension program the projection proves nothing.
    assert_ne!(
        reason("omp", "python3 app.py > out.txt && git add -A", &ws, false),
        CONTAINED
    );
}

#[test]
fn git_commands_that_write_sandbox_denied_metadata_stay_out_of_the_sandbox() {
    let ws = workspace("git-metadata", true);
    for command in [
        "git worktree add -b report ../report-wt main && ls ../report-wt",
        "mkdir -p .git/worktrees; git worktree add ../wt main",
        "git config user.name Agent && git commit -m x",
        "git remote add origin https://example.com/x.git",
        "git branch -m main trunk",
        "git submodule add ../lib lib",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
}

/// Whether this host runs the workspace sandbox at all.
pub(super) fn host() -> bool {
    crate::pretool::workspace_contained::sandbox_available()
}

/// The host `PATH`, led by a Node the sandbox may run. Hosted runners keep
/// Node where the sandbox will not execute from, so a version manager's
/// directory under `home` stands in for it.
#[cfg(unix)]
fn path_with_node(home: &Path) -> String {
    use std::os::unix::fs::PermissionsExt;
    let bin = home.join(".nvm/versions/node/v25.2.1/bin");
    std::fs::create_dir_all(&bin).unwrap();
    for name in ["node", "npm"] {
        let tool = bin.join(name);
        std::fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap())
}

#[cfg(not(unix))]
fn path_with_node(_home: &Path) -> String {
    std::env::var("PATH").unwrap()
}

/// A linked worktree keeps its index, `HEAD`, refs and objects in the main
/// checkout's shared Git directory, which `workspace-contained-v1` grants the
/// run, so ordinary Git there is bounded exactly as it is in a main checkout.
#[test]
fn a_linked_worktree_contains_git_with_its_shared_directory() {
    let root = std::env::temp_dir().join(format!("guard-ws-{}-linked", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (main, tree) = (root.join("main"), root.join("tree"));
    let admin = main.join(".git/worktrees/tree");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::create_dir_all(&tree).unwrap();
    let (main, tree) = (main.canonicalize().unwrap(), tree.canonicalize().unwrap());
    let admin = admin.canonicalize().unwrap();
    std::fs::write(main.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", tree.join(".git").display()),
    )
    .unwrap();
    std::fs::write(tree.join(".git"), format!("gitdir: {}\n", admin.display())).unwrap();
    std::fs::write(tree.join("package.json"), "{}").unwrap();
    for command in ["rm notes.txt", "npm run build", "chmod +x scripts/run.sh"] {
        let got = reason("omp", command, &tree, true);
        // macOS claims the build with its narrower node build-output profile.
        let narrower = cfg!(target_os = "macos")
            && command == "npm run build"
            && got == "native_node_build_output_containment_required";
        assert_eq!(got == CONTAINED || narrower, host(), "{command}");
    }
    // Its index, reflog and objects are the shared Git directory's, which the
    // sandbox grants the run, so these are bounded as in a main checkout.
    for command in [
        "git add -A && git commit -m x",
        "git commit -m init",
        "git stash",
    ] {
        assert_eq!(
            reason("omp", command, &tree, true) == CONTAINED,
            host(),
            "{command}"
        );
    }
    // The shared configuration, hooks and the other worktrees' entries stay
    // write-denied, so Git that has to write one keeps its review.
    for command in [
        "git worktree remove --force ../other",
        "git config user.email agent@example.com",
        "git push origin HEAD",
        // Rebase, sequencer, bisect and squash state are outside the grant.
        "git rebase main",
        "git cherry-pick HEAD~1",
        "git revert --no-edit HEAD",
        "git bisect start",
        "git am -3 fix.patch",
        "git merge --squash main",
    ] {
        assert_ne!(reason("omp", command, &tree, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn reviewable_settings_run_with_their_command_in_the_workspace_sandbox() {
    let ws = workspace("settings", true);
    for command in [
        "PORT=4173 npm run build",
        "PORT=4173 VITE_MODE=test npm run lint",
        "PORT=4173 ./todo.py add x",
    ] {
        assert_eq!(
            reason("omp", command, &ws, true) == CONTAINED,
            host(),
            "{command}"
        );
    }
    // Settings that swap the program, its loader or its credentials, and
    // commands the sandbox cannot bound, keep their review.
    for command in [
        "NODE_OPTIONS=--require=./x.js npm run build",
        "PATH=/tmp/bin:/usr/bin npm run build",
        "GITHUB_TOKEN=x npm run build",
        "PORT=4173 curl https://example.com",
        "PORT=4173 sudo npm run build",
        "PORT=4173 cat /Users/nobody/.ssh/id_rsa",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    assert_ne!(
        reason("cursor", "PORT=4173 npm run build", &ws, true),
        CONTAINED
    );
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn private_temp_paths_run_in_the_workspace_sandbox() {
    let ws = workspace("private-temp", true);
    for command in [
        "OUT_DIR=\"$TMPDIR/report-test\" npm run build",
        "OUT_DIR=\"${TMPDIR}/report-test\" npm run build",
        "OUT_DIR=$TMPDIR/report-test PORT=4173 npm run build",
        "OUT_DIR=\"${TMPDIR:-/tmp}/report-test\" npm run build",
    ] {
        assert_eq!(
            reason("omp", command, &ws, true) == CONTAINED,
            host(),
            "{command}"
        );
    }
    // A runner reaches the sandbox only once its tool is installed, since
    // `bunx` would otherwise fetch it; macOS may claim it with a narrower
    // node profile first.
    let runner = "OUT_DIR=\"$TMPDIR/report-test\" bunx vitest run src/report.test.ts";
    assert_ne!(reason("omp", runner, &ws, true), CONTAINED);
    std::fs::create_dir_all(ws.join("node_modules/.bin")).unwrap();
    std::fs::write(ws.join("node_modules/.bin/vitest"), "#!/bin/sh\n").unwrap();
    if cfg!(target_os = "linux") && host() {
        assert_eq!(reason("omp", runner, &ws, true), CONTAINED);
    }
    // Another variable, a rebound TMPDIR, a default or a command
    // substitution could name a host directory, and a single-quoted `$` is
    // left for the program to expand.
    for command in [
        "OUT_DIR=\"$HOME/report-test\" npm run build",
        "OUT_DIR=\"$TMPDIR/$(id -un)\" npm run build",
        "OUT_DIR=\"$TMPDIR/`id -un`\" npm run build",
        "OUT_DIR=\"${TMPDIR:-/Users/nobody}/x\" npm run build",
        "OUT_DIR=\"$TMPDIRS/x\" npm run build",
        "OUT_DIR='$TMPDIR/x' npm run build",
        "TMPDIR=/Users/nobody/.ssh OUT_DIR=\"$TMPDIR/x\" npm run build",
        "export TMPDIR=/Users/nobody && OUT_DIR=\"$TMPDIR/x\" npm run build",
        "OUT_DIR=\"$HOME/x\" bunx vitest run src/report.test.ts",
        "TMPDIR=/Users/nobody OUT_DIR=\"$TMPDIR/x\" bunx vitest run src/report.test.ts",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn recursive_removal_runs_in_the_sandbox_only_for_ignored_or_missing_targets() {
    let root = std::env::temp_dir().join(format!("guard-ws-{}-removal", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (home, repo) = (root.join("home"), root.join("repo"));
    for directory in [&home, &repo.join("dist"), &repo.join("src")] {
        std::fs::create_dir_all(directory).unwrap();
    }
    assert!(std::process::Command::new("git")
        .args(["init", "--quiet"])
        .arg(&repo)
        .status()
        .unwrap()
        .success());
    std::fs::write(repo.join(".gitignore"), "dist/\n").unwrap();
    std::fs::write(repo.join("dist/out.js"), "1").unwrap();
    std::fs::write(repo.join("src/a.ts"), "1").unwrap();
    let (home, repo) = (home.canonicalize().unwrap(), repo.canonicalize().unwrap());
    let environment = guard_contracts::GuardExecutionEnvironmentV1 {
        path: path_with_node(&home),
        environment_names: vec!["GIT_CONFIG_NOSYSTEM".into()],
        environment_digest: "0".repeat(64),
        home: home.to_str().map(str::to_owned),
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: true,
        library_search_paths: Default::default(),
    };
    let controls = controls();
    let reason = |command: &str| {
        crate::pretool::evaluate_pre_tool_envelope_with_execution_context(
            "omp",
            "PreToolUse",
            &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
            Some(&controls),
            None,
            crate::pretool::PathContext {
                home_dir: home.to_str(),
                cwd: repo.to_str(),
                ..Default::default()
            },
            Some(&environment),
        )
        .reason_code
    };
    // Git answers for a lone recursive removal of a missing target on every
    // platform, before the sandbox is asked. Git cannot restore ignored
    // files, so `dist` is left to the sandbox.
    let missing = "rm -rf coverage";
    assert_eq!(
        reason(missing),
        "native_exact_safe_recoverable_removal",
        "{missing}"
    );
    for command in [
        "rm -rf dist",
        "rm -rf dist && npm run build",
        "rm src/a.ts",
        "rm -f src/a.ts dist/out.js",
        "sed --in-place=.orig -n 'p' src/a.ts && rm -f src/a.ts.orig",
    ] {
        let got = reason(command);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
    // A plain substitution on a workspace file is proven on the host. The
    // GNU operand form is proven only where GNU sed parses it that way.
    for (command, proven) in [
        ("sed -i 's/1/2/' src/a.ts", cfg!(target_os = "linux")),
        ("sed -i '' -e 's/1/2/g' src/a.ts", true),
        ("sed -E -i.bak 's/(1)/2/' src/a.ts", true),
    ] {
        let got = reason(command);
        if proven {
            assert_eq!(got, "native_exact_safe_command", "{command}");
        } else if host() {
            assert_eq!(got, CONTAINED, "{command}");
        }
    }
    // The `e` flag runs the pattern space as a command; it is never proven.
    let exec = "sed -i '' 's/1/2/e' src/a.ts";
    assert_ne!(reason(exec), "native_exact_safe_command", "{exec}");
    // A tracked or unknown tree may hold uncommitted work the sandbox would
    // write back as deleted.
    for command in [
        "rm -rf src",
        "rm -rf src 2>&1",
        "rm -rf dist src",
        "rm -rf *.egg-info",
        "npm run build && rm -rf dist",
        "cd src && rm -rf .",
        "rm -rf $DIR",
        "shred -u src/a.ts",
        "truncate -s 0 src/a.ts",
        "rm --no-preserve-root -rf dist",
        "GLOBIGNORE=x rm -rf dist",
        "sed --follow-symlinks -i 's/1/2/' src/a.ts",
        "LC_ALL=C sed -i 's/1/2/' src/a.ts",
    ] {
        assert_ne!(reason(command), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// `timeout 30 pytest -q` runs the program the text already names, under a
/// clock that signals that one child, so this route reaches the same verdict
/// it reaches for the command without the clock. `sudo` changes who runs the
/// program and keeps the command off the route either way.
#[test]
fn a_timeout_clock_keeps_the_command_it_wraps_in_the_sandbox() {
    let ws = workspace("timeout-wrapper", true);
    for command in [
        "python3 app.py",
        "./todo.py add x",
        "git commit -m init",
        "rm -f *.pyc",
        "npm run build && git diff",
    ] {
        assert_eq!(
            reason("omp", &format!("timeout 30 {command}"), &ws, true),
            reason("omp", command, &ws, true),
            "{command}"
        );
        assert_eq!(
            reason("omp", &format!("timeout -- 5s {command}"), &ws, true),
            reason("omp", command, &ws, true),
            "{command}"
        );
    }
    assert_eq!(
        reason("omp", "timeout 60 npm run build", &ws, true) == CONTAINED,
        host()
    );
    for command in [
        "timeout 30 sudo npm run build",
        "sudo timeout 30 npm run build",
        "timeout 30 curl https://example.com",
        "timeout 30 cat /Users/nobody/.ssh/id_rsa",
        "timeout 30 git push origin main",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}
