#![cfg(unix)]

//! Reads, listings and new files outside the session workspace: sibling
//! checkouts and new home directories are ordinary working space, while
//! credential contents, home dotfiles and tool configuration stay reviewed.

use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: &Path, content: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, content).unwrap();
}

fn fixture(name: &str) -> Fixture {
    // Avoid macOS's protected /private/var temporary root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-outside-workspace-files")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    for repository in ["project", "sibling"] {
        let path = home.join("code").join(repository);
        std::fs::create_dir_all(&path).unwrap();
        assert!(Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&path)
            .status()
            .unwrap()
            .success());
    }
    let sibling = home.join("code/sibling");
    write(
        &sibling.join("package.json"),
        "{\"scripts\":{\"build\":\"tsc\"}}\n",
    );
    write(&sibling.join("src/index.ts"), "export {};\n");
    write(&sibling.join("tests/index.test.ts"), "export {};\n");
    write(&sibling.join("existing.txt"), "keep\n");
    write(&sibling.join(".env"), "SYNTHETIC_ONLY=fixture\n");
    write(
        &home.join("kubeconfig.yaml"),
        "apiVersion: v1\nkind: Config\n",
    );
    write(&home.join(".ssh/id_rsa"), "synthetic fixture\n");
    write(
        &home.join(".bun/install/global/node_modules/vite/package.json"),
        "{}\n",
    );
    write(&home.join(".bun/install/cache/entry.json"), "{}\n");
    write(
        &home.join(".nvm/.cache/node_modules/left-pad/package.json"),
        "{}\n",
    );
    write(
        &home.join(".nvm/versions/node/v1.0.0/lib/node_modules/npm/package.json"),
        "{}\n",
    );
    let home = std::fs::canonicalize(&home).unwrap();
    Fixture {
        root,
        project: home.join("code/project"),
        home,
    }
}

fn decision(fixture: &Fixture, harness: &str, input: Value) -> String {
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &input,
        None,
        None,
        fixture.home.to_str(),
        fixture.project.to_str(),
    )
    .minimum_action
}

fn shell_allowed(fixture: &Fixture, command: &str) -> bool {
    let input = json!({"toolName": "Bash", "toolInput": {"command": command}});
    let zcode = decision(fixture, "zcode", input.clone());
    assert_eq!(
        zcode,
        decision(fixture, "omp", input),
        "host policy drift: {command}"
    );
    zcode == "allow"
}

fn write_allowed(fixture: &Fixture, path: &str) -> bool {
    let input = json!({"toolName": "Write", "toolInput": {"file_path": path, "content": "x\n"}});
    decision(fixture, "claude-code", input) == "allow"
}

fn check(fixture: &Fixture, allowed: &[&str], reviewed: &[&str]) {
    for command in allowed {
        assert!(shell_allowed(fixture, command), "{command}");
    }
    for command in reviewed {
        assert!(!shell_allowed(fixture, command), "{command}");
    }
}

#[test]
fn new_files_and_directories_outside_the_workspace() {
    let fixture = fixture("creates");
    check(
        &fixture,
        &[
            "mkdir -p ~/deliverables",
            "mkdir ~/code/sibling/reports",
            "touch ~/code/sibling/notes.txt",
            "touch -- ~/code/sibling/src/new.ts",
        ],
        &[
            "mkdir -p ~/.deliverables",
            "mkdir -p ~/bin",
            "mkdir -p ~/code/sibling/.husky",
            "mkdir -p ~/code/sibling/.git/hooks",
            "touch ~/.probe",
            "touch ~/code/sibling/.envrc",
            "touch ~/code/sibling/.zcode/x",
            "mkdir -p ~/code/sibling/.copilot/a",
            "mkdir -p ~/code/sibling/.opencode/plugins",
            "cp -R ~/code/sibling/src ~/code/sibling/.clinerules/",
            "touch ~/Library/LaunchAgents/probe.plist",
            "touch ~/code/sibling/existing.txt && rm ~/code/sibling/existing.txt",
        ],
    );
}

#[test]
fn plain_dot_scratch_writes_in_sibling_checkouts() {
    let fixture = fixture("dot-scratch");
    let sibling = fixture.home.join("code/sibling");
    for name in [".write-test", ".tmp/validate.mjs", ".scratch/notes.md"] {
        let path = sibling.join(name);
        assert!(write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
    let code = fixture.home.join("code/.probe.txt");
    assert!(write_allowed(&fixture, code.to_str().unwrap()), "org probe");
    for name in [
        ".envrc",
        ".env.local",
        ".npmrc",
        ".yarnrc.yml",
        ".bunfig.toml",
        ".gitattributes",
        ".gitmodules",
        ".git/hooks/pre-commit",
        ".husky/pre-commit",
        ".pre-commit-config.yaml",
        ".vscode/tasks.json",
        ".github/workflows/ci.yml",
        ".claude/settings.json",
        ".codex/config.toml",
        ".cursor/mcp.json",
        ".mcp.json",
        ".tmp/.envrc",
        ".opencode/plugins/x.ts",
        ".zcode/x",
        ".zcode-plugin/x.json",
        ".copilot/a/x.md",
        ".clinerules/x.md",
        ".vscode-insiders/settings.json",
        ".kiro/steering/x.md",
        ".roo/rules/x.md",
        ".dockerignore/notes.md",
        ".newagent/rules.md",
    ] {
        let path = sibling.join(name);
        assert!(!write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
    for name in [".probe", ".tmp/probe.txt", ".bashrc"] {
        let path = fixture.home.join(name);
        assert!(!write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
}

#[test]
fn framework_build_output_writes_in_sibling_checkouts() {
    let fixture = fixture("build-output");
    let sibling = fixture.home.join("code/sibling");
    for name in [
        ".next/cache/webpack/index.pack",
        ".next/server/app/page.js",
        ".nuxt/dist/server.mjs",
        ".svelte-kit/output/index.js",
        ".turbo/runs/build.log",
        ".parcel-cache/data.mdb",
        "node_modules/.cache/babel-loader/a.json",
        "node_modules/.vite/deps/chunk.js",
    ] {
        let path = sibling.join(name);
        assert!(write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
    for name in [
        // The names are cache directories only where a framework writes them.
        ".cache/x.json",
        ".vite/x.js",
        "src/.cache/x.json",
        "node_modules/pkg/.cache/x.json",
        "node_modules/.bin/tool",
        "node_modules/.husky/pre-commit",
        // A guarded name stays guarded below a build directory.
        ".next/.envrc",
        ".next/.git/hooks/pre-commit",
        ".next/.husky/pre-commit",
        ".turbo/.claude/settings.json",
        ".output/.npmrc",
        ".next-extra/x.js",
    ] {
        let path = sibling.join(name);
        assert!(!write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
    for name in [".next/server/page.js", "node_modules/.cache/a.json"] {
        let path = fixture.project.join(name);
        assert!(write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
    let path = fixture.project.join(".next/.envrc");
    assert!(!write_allowed(&fixture, path.to_str().unwrap()));
    for name in [".next/x.js", ".turbo/x.log", ".cache/x.json"] {
        let path = fixture.home.join(name);
        assert!(!write_allowed(&fixture, path.to_str().unwrap()), "{name}");
    }
}

#[test]
fn credential_files_allow_metadata_but_not_contents() {
    let fixture = fixture("metadata");
    check(
        &fixture,
        &[
            "ls -la ~/kubeconfig.yaml",
            "ls -la ~/kubeconfig.yaml 2>&1 | head -2",
        ],
        &[
            "cat ~/kubeconfig.yaml",
            "head -5 ~/kubeconfig.yaml",
            "ls -la ~/.ssh/id_rsa",
            "ls -la ~/.ssh",
            "cat ~/code/sibling/.env",
        ],
    );
}

#[test]
fn global_package_trees_list_without_nested_hidden_tool_state() {
    let fixture = fixture("global-packages");
    check(
        &fixture,
        &[
            "ls ~/.bun/install/global/node_modules",
            "ls ~/.bun/install/global/node_modules 2>/dev/null",
            "ls ~/.nvm/versions/node/v1.0.0/lib/node_modules/",
            "ls -la ~/.nvm/versions/node/v1.0.0/lib/node_modules/npm",
            // Installed package trees are readable source; a recursive
            // listing shows only their file names.
            "ls -R ~/.bun/install/global/node_modules",
            // Tool directories below a home dot-directory list by name.
            "ls ~/.bun/install/cache",
            "ls ~/.bun",
        ],
        &["ls ~/.nvm/.cache/node_modules"],
    );
}

#[test]
fn global_package_links_into_tool_caches_stay_reviewed() {
    let fixture = fixture("package-links");
    let cache = fixture.home.join(".bun/install/cache/node_modules/pkg");
    write(&cache.join("package.json"), "{}\n");
    let global = fixture.home.join(".bun/install/global/node_modules");
    std::os::unix::fs::symlink(&cache, global.join("linked")).unwrap();
    let nvm_cache = fixture.home.join(".nvm/.cache/node_modules");
    let nvm_lib = fixture.home.join(".nvm/versions/node/v2.0.0/lib");
    std::fs::create_dir_all(&nvm_lib).unwrap();
    std::os::unix::fs::symlink(&nvm_cache, nvm_lib.join("node_modules")).unwrap();
    std::os::unix::fs::symlink(
        fixture.home.join("code/sibling"),
        global.join("linked-checkout"),
    )
    .unwrap();
    check(
        &fixture,
        &[
            "ls ~/.bun/install/global/node_modules",
            "ls -la ~/.bun/install/global/node_modules/vite",
            "ls ~/.bun/install/global/node_modules/linked-checkout",
            "ls ~/.bun/install/cache/node_modules/pkg",
        ],
        &[
            "ls ~/.bun/install/global/node_modules/linked",
            "ls -la ~/.bun/install/global/node_modules/linked/",
            "ls ~/.nvm/versions/node/v2.0.0/lib/node_modules",
        ],
    );
}

#[test]
fn jq_pipelines_reshape_without_reaching_input_or_environment() {
    let fixture = fixture("jq");
    check(
        &fixture,
        &[
            "jq -r '.scripts | keys | length' ~/code/sibling/package.json",
            "jq '.scripts|keys_unsorted|sort' ~/code/sibling/package.json",
            "jq -r '.scripts | keys[]' ~/code/sibling/package.json",
            "jq -r '.scripts | to_entries[] | .key' ~/code/sibling/package.json",
            "jq -r '.scripts | has(\"build\")' ~/code/sibling/package.json",
            "jq -r '.scripts | keys | join(\"\\n\")' ~/code/sibling/package.json",
            "cat ~/code/sibling/package.json | jq -r '.key'",
        ],
        &[
            "jq -r '.scripts | has(\"\\(env)\")' ~/code/sibling/package.json",
            "jq -r '.scripts | test(\"x\")' ~/code/sibling/package.json",
            "jq -r '.name' ~/code/sibling/server.key",
            "jq -r '.name' ~/code/sibling/.key",
            "jq -r '.scripts | env' ~/code/sibling/package.json",
            "jq -r '.scripts | input' ~/code/sibling/package.json",
            "jq -r '.scripts | $ENV' ~/code/sibling/package.json",
            "jq -r '.scripts | keys' ~/code/sibling/.env",
        ],
    );
}

#[test]
fn write_probe_removes_only_the_file_it_created() {
    let fixture = fixture("probe");
    check(
        &fixture,
        &[
            "touch ~/code/sibling/probe.txt && echo ok || echo fail; rm -f ~/code/sibling/probe.txt 2>/dev/null",
            "touch ~/code/sibling/probe.txt && rm ~/code/sibling/probe.txt",
        ],
        &[
            "touch ~/code/sibling/existing.txt && echo ok; rm -f ~/code/sibling/existing.txt",
            "touch ~/code/sibling/probe.txt; rm -f ~/code/sibling/existing.txt",
            "touch ~/code/sibling/probe.txt && cat ~/code/sibling/.env; rm -f ~/code/sibling/probe.txt",
            "touch ~/code/sibling/probe.txt | rm -f ~/code/sibling/probe.txt",
            "touch ~/.probe && rm -f ~/.probe",
            "touch '~/code/sibling/probe.txt' && rm -f '~/code/sibling/probe.txt'",
            "rm -f ~/code/sibling/existing.txt",
        ],
    );
}

#[test]
fn write_probe_removes_only_the_directory_it_created() {
    let fixture = fixture("probe-directory");
    check(
        &fixture,
        &[
            "mkdir ~/code/sibling/probe-dir && echo ok; rm -rf ~/code/sibling/probe-dir",
            "mkdir -p ~/code/sibling/probe-dir && rm -r -- ~/code/sibling/probe-dir",
            "mkdir -p ~/code/sibling/src/probe && rm -rf ~/code/sibling/src/probe",
        ],
        &[
            "mkdir -p ~/code/sibling/src && rm -rf ~/code/sibling/src",
            "mkdir -p ~/code/sibling/probe-dir && rm -rf ~/code/sibling/src",
            "mkdir -p ~/code/sibling/new/../src && rm -rf ~/code/sibling/new/../src",
            "mkdir -p ~/code/sibling/probe-dir && rm -f ~/code/sibling/probe-dir",
            "touch ~/code/sibling/probe.txt && rm -rf ~/code/sibling/probe.txt",
            "mkdir -p ~/code/sibling/probe-dir && cat ~/code/sibling/.env; rm -rf ~/code/sibling/probe-dir",
            "mkdir -p ~/code/sibling/probe-* && rm -rf ~/code/sibling/probe-*",
            "mkdir -p '~/code/sibling/probe-dir' && rm -rf '~/code/sibling/probe-dir'",
            "mkdir -p \\~/code/sibling/probe-dir && rm -rf \\~/code/sibling/probe-dir",
            "rm -rf ~/code/sibling/probe-dir",
        ],
    );
}

#[test]
fn cd_sequences_prove_reads_in_both_directories() {
    let fixture = fixture("cd-sequence");
    // A `~` operand to `cd` is proven only when the shell's HOME matches the
    // declared one, which an in-process evaluation cannot show; use absolute
    // paths so the sequence proof itself is exercised.
    let sibling = fixture.home.join("code/sibling");
    let ssh = fixture.home.join(".ssh");
    let (sibling, ssh) = (sibling.display(), ssh.display());
    let allowed = [
        format!("cd {sibling} && ls src; ls tests"),
        format!("cd {sibling} && ls src; ls tests; ls"),
        format!("cd {sibling}; ls src"),
        format!("cd {sibling} && ls src; ls tests;"),
        format!("cd {sibling} && ls; node --version"),
        format!("cd {sibling} && node -v; ls"),
        format!("cd {sibling} && cat package.json && python3 --version"),
    ];
    let reviewed = [
        format!("cd {sibling} && ls src; cat .env"),
        format!("cd {sibling} && ls src; rm -f existing.txt"),
        format!("cd {sibling} || ls src; ls tests"),
        format!("cd {ssh} && ls; ls"),
        format!("cd {sibling} && ls; node -e 1"),
        format!("cd {sibling} && ls; node src/index.ts"),
        format!("cd {sibling} && ls; pnpm --version"),
        format!("cd {sibling} && ls; yarn --version"),
        format!("cd {sibling} && ls; ;"),
    ];
    let allowed: Vec<&str> = allowed.iter().map(String::as_str).collect();
    let reviewed: Vec<&str> = reviewed.iter().map(String::as_str).collect();
    check(&fixture, &allowed, &reviewed);
}

#[test]
fn write_probe_cleanup_is_not_a_destructive_delete_under_default_controls() {
    use guard_command::native_command_controls::CompiledNativeCommandControls;
    use guard_command::native_command_program::packaged_command_program;
    use guard_contracts::NativeCommandControlBindingV1;

    let fixture = fixture("probe-controls");
    let program = packaged_command_program().unwrap();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(json!({
        "schema": "guard.native-command-control-binding.v1",
        "program_digest": program.program_digest, "catalog_digest": program.catalog_digest,
        "trust_digest": program.trust_digest, "health": "protected", "revision": 1,
        "managed_revision": 0, "effective_digest": "", "layers": []
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let controls = CompiledNativeCommandControls::new(&binding).unwrap();
    let action = |command: &str| {
        evaluate_pre_tool_envelope_with_context(
            "zcode",
            "PreToolUse",
            &json!({"toolName": "Bash", "toolInput": {"command": command}}),
            Some(&controls),
            None,
            fixture.home.to_str(),
            fixture.project.to_str(),
        )
        .minimum_action
    };
    for command in [
        "touch ~/code/sibling/probe.txt && echo ok || echo fail; rm -f ~/code/sibling/probe.txt",
        "touch ~/code/sibling/probe.txt && rm ~/code/sibling/probe.txt",
    ] {
        assert_eq!(action(command), "allow", "{command}");
    }
    for command in [
        "touch ~/code/sibling/existing.txt && rm -f ~/code/sibling/existing.txt",
        "touch ~/code/sibling/probe.txt; rm -f ~/code/sibling/existing.txt",
        "rm -f ~/code/sibling/existing.txt",
        "rm -f ~/code/sibling/probe.txt",
    ] {
        assert_ne!(action(command), "allow", "{command}");
    }
}
