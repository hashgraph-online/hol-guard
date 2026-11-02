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
        // Signal 0 delivers nothing, so these ask whether a process is still
        // there and leave every process they name running.
        "kill -0 4821",
        "kill -s 0 4821",
        "kill -n 0 4821 7312",
        "kill -0 %1",
        "rm -f init_repo.py",
        "rm a.py && rm -rf __pycache__",
        "echo hi > scratch.txt && rm scratch.txt",
        "rmdir node_modules/zod-dir",
        "rm -d build",
        "yarn build",
        // Printing the project's own workspaces runs nothing in them.
        "yarn workspaces list",
        "yarn workspaces list --json",
        "pnpm run test:unit",
        // These Git forms keep every uncommitted change reachable.
        "git switch -c feature/login-form",
        "git checkout -b fix-1",
        "git stash",
        "git stash push -m 'wip: parser'",
        // A pathspec keeps strictly less work than the unbounded form does,
        // and the entry still holds every change the command moves.
        "git stash push -- src/app.py",
        "git stash push src/app.py",
        "git stash push -m 'warm cache' -- src/app.py",
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

/// Narrower node profiles claim these commands before the general workspace
/// profile; each is at least as tightly bounded, or needs no sandbox at all.
/// Every host whose sandbox can start a contained run routes them -- macOS
/// under Seatbelt, Linux under a bubblewrap mount -- so the profile is asked
/// of `host()` rather than of one operating system.
#[test]
fn node_commands_with_a_narrower_profile_keep_it() {
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
        if host() {
            assert_eq!(got, narrower, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
}

/// Inline `node -e` has its own, narrower read-only containment profile, which
/// runs before the general workspace profile and bounds the command at least
/// as tightly, on every host whose sandbox can start a contained run.
#[test]
fn inline_node_eval_keeps_its_read_only_containment_profile() {
    let ws = workspace("node-eval", true);
    let got = reason("omp", "node -e 1", &ws, true);
    if host() {
        assert_eq!(got, "native_node_eval_readonly_containment_required");
    } else {
        assert_ne!(got, CONTAINED);
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
        // The exception is signal 0 with an operand that names a process:
        // a negative operand asks about every process the user can reach,
        // and a signal that is only spelled like 0 is a different signal.
        "kill -0 -1",
        "kill -0 -4821",
        "kill -00 4821",
        "kill -s SIGNULL 4821",
        "kill -0",
        // Pid `0` asks about the caller's own process group, which is the
        // same survey a negative operand asks for, and a leading zero writes
        // both of those another way.
        "kill -0 0",
        "kill -0 00",
        "kill -0 01",
        "kill -s 0 0",
        // Arithmetic stands for a number by the time the operands are read,
        // so the words the caller wrote are what this form admits.
        "kill -0 $((-1))",
        "kill -0 $((4821))",
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
        // `focus` installs, `foreach` runs a command of its own in each
        // workspace, and a bare `workspaces` names neither, so the subcommand
        // still has to say what runs.
        "yarn workspaces focus",
        "yarn workspaces focus web",
        "yarn workspaces foreach run build",
        "yarn workspaces",
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

/// Whether this host runs the workspace sandbox at all.
pub(super) fn host() -> bool {
    crate::pretool::workspace_contained::sandbox_available()
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
