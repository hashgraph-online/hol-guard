//! Guard's managed agent instructions tell Codex to read
//! `~/.hol-support/SAFETY.md` first, and Codex chains that read with its first
//! look at the project. The sandbox launcher copies the guide into the private
//! home, so the chain runs in the workspace sandbox like the listing alone.
//! Any other home path, including one that walks out of `.hol-support`, keeps
//! its review.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const CONTAINED: &str = "native_workspace_containment_required";

/// A home and project below the target directory: macOS `$TMPDIR` resolves
/// under `/private/var`, which the sensitive-path screen rejects.
struct Fixture {
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/contained-safety-guide-tests")
            .join(format!(
                "run-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        let project = root.join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
        for (relative, text) in [
            (".hol-support/SAFETY.md", "Read before acting.\n"),
            (".ssh/id_rsa", "fixture\n"),
            ("project/package.json", "{\"name\":\"game\"}\n"),
            ("project/README.md", "# game\n"),
            ("project/index.html", "<!doctype html>\n"),
            ("project/src/game.js", "module.exports = {};\n"),
        ] {
            let path = root.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let home = root.canonicalize().unwrap();
        let project = project.canonicalize().unwrap();
        Self { home, project }
    }

    fn classify(&self, command: &str) -> PreToolResultV1 {
        evaluate_pre_tool_envelope_with_context(
            "codex",
            "PreToolUse",
            &json!({"tool_name": "Bash", "tool_input": {"command": command}}),
            Some(&controls()),
            None,
            self.home.to_str(),
            self.project.to_str(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn controls() -> guard_command::native_command_controls::CompiledNativeCommandControls {
    let program = guard_command::native_command_program::packaged_command_program().unwrap();
    let mut binding: guard_contracts::NativeCommandControlBindingV1 =
        serde_json::from_value(json!({
            "schema": "guard.native-command-control-binding.v1",
            "program_digest": program.program_digest,
            "catalog_digest": program.catalog_digest,
            "trust_digest": program.trust_digest,
            "health": "protected",
            "revision": 1,
            "managed_revision": 0,
            "effective_digest": "",
            "layers": []
        }))
        .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    guard_command::native_command_controls::CompiledNativeCommandControls::new(&binding).unwrap()
}

#[test]
fn the_safety_guide_read_chained_with_a_listing_runs_in_the_sandbox() {
    let fixture = Fixture::new();
    for command in [
        "cat ~/.hol-support/SAFETY.md && rg --files -g 'AGENTS.md' -g 'package.json' -g 'README*' -g 'index.html' -g 'src/**' -g 'test*' -g 'vite.config.*' -g 'tsconfig*' -g '.gitignore'",
        "cat ~/.hol-support/SAFETY.md && rg --files -g 'AGENTS.md' -g 'package.json' -g 'README*' -g 'pyproject.toml' -g 'Cargo.toml' -g 'go.mod' -g 'Makefile' -g 'vite.config.*' -g 'src/**' -g 'app/**' -g 'test*' -g '*lock*' | head -100",
        "sed -n '1,240p' ~/.hol-support/SAFETY.md && rg --files -g 'src/**'",
    ] {
        let result = fixture.classify(command);
        if cfg!(target_os = "macos") {
            assert_ne!(
                result.minimum_action, "review",
                "{command}: {}",
                result.reason
            );
            if result.minimum_action != "allow" {
                assert_eq!(result.reason_code, CONTAINED, "{command}");
            }
        }
    }
}

#[test]
fn other_home_reads_chained_with_a_listing_keep_their_review() {
    let fixture = Fixture::new();
    for command in [
        "cat ~/.ssh/id_rsa && rg --files -g 'src/**'",
        "cat ~/.hol-support/../.ssh/id_rsa && rg --files -g 'src/**'",
        "cat ~/.hol-support/SAFETY.md ~/.ssh/id_rsa && rg --files -g 'src/**'",
        "cp ~/.hol-support/SAFETY.md notes.md && rg --files -g 'src/**'",
        "cat ~/.hol-support/SAFETY.md > ~/.zshrc && rg --files -g 'src/**'",
        "export HOME=. && cat ~/.hol-support/SAFETY.md && rg --files -g 'src/**'",
        "HOME=. cat ~/.hol-support/SAFETY.md && rg --files -g 'src/**'",
    ] {
        let result = fixture.classify(command);
        assert_ne!(result.minimum_action, "allow", "{command}");
        assert_ne!(result.reason_code, CONTAINED, "{command}");
    }
    for listing in [
        "rg --hidden --files",
        "rg --no-ignore --files",
        "rg --follow --files",
        "rg --pre cat --files",
    ] {
        let command = format!("cat ~/.hol-support/SAFETY.md && {listing}");
        let result = fixture.classify(&command);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}
