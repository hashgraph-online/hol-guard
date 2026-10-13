use crate::native_command_controls::CompiledNativeCommandControls;
use crate::native_command_program::packaged_command_program;
use guard_contracts::NativeCommandControlBindingV1;
use std::path::PathBuf;

fn controls() -> CompiledNativeCommandControls {
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

fn workspace(name: &str, git: bool) -> PathBuf {
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

fn reason(harness: &str, command: &str, cwd: &std::path::Path, with_controls: bool) -> String {
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

const CONTAINED: &str = "native_workspace_containment_required";

#[test]
fn unproven_local_commands_run_in_the_workspace_sandbox_on_macos() {
    let ws = workspace("convert", true);
    for command in [
        "./todo.py add x",
        "node -e 1",
        "python3 app.py",
        "mkdir -p src && touch src/a.js",
        "git add -A && git commit -m x",
        "npm run build && git diff",
        "rm -rf dist node_modules",
        "rm -rf ./build/ && npm run build",
        "rm -f *.pyc",
        "rm notes.txt",
        "rm -f init_repo.py",
        "rm a.py && rm -rf __pycache__",
        "echo hi > scratch.txt && rm scratch.txt",
        "rmdir node_modules/zod-dir",
        "rm -d build",
        "cat package.json > copy.json && head -3 copy.json",
        "find src -type f > files.txt; wc -l files.txt",
        "npm run lint",
        "npm -v",
        "yarn build",
        "pnpm run test:unit",
        "bun run build",
        "/Users/nobody/.nvm/versions/node/v25.2.1/bin/npm run build",
    ] {
        let got = reason("omp", command, &ws, true);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
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
        "npm install",
        "sudo ls",
        "chmod 777 x",
        "echo $(x)",
        "echo hi > ../out",
        "git reset --hard",
        "git checkout main",
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
        "pip list",
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
fn host() -> bool {
    cfg!(target_os = "macos") || crate::restricted_pytest::linux_workspace_sandbox_available()
}
