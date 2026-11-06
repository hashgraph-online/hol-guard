//! `pkill -f '<interpreter> <script>'` stopping a server started from a script
//! in the workspace needs no approval; broader process signals keep theirs.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use guard_contracts::PreToolResultV1;
use serde_json::json;
use std::path::{Path, PathBuf};

struct Fixture {
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/process-stop-tests")
            .join(format!("run-{}", std::process::id()));
        let project = root.join("project");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        std::fs::write(project.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
        for file in ["server.js", "hol-guard.js", "src/app.py"] {
            let path = project.join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "\n").unwrap();
        }
        Self {
            home: root.canonicalize().unwrap(),
            project: project.canonicalize().unwrap(),
        }
    }

    fn classify(&self, harness: &str, command: &str) -> PreToolResultV1 {
        evaluate_pre_tool_envelope_with_context(
            harness,
            "PreToolUse",
            &json!({"tool_name": "bash", "tool_input": {"command": command}}),
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
fn stopping_a_workspace_server_and_its_broad_neighbours() {
    let fixture = Fixture::new();
    for harness in ["omp", "claude-code", "codex"] {
        for command in [
            "pkill -f 'node server.js' || true",
            "pkill -f 'node server.js'",
            "pkill -INT -f 'python3 src/app.py'",
        ] {
            let result = fixture.classify(harness, command);
            assert_eq!(
                result.minimum_action, "allow",
                "{harness}: {command}: {}",
                result.reason_code
            );
        }
        for command in [
            "pkill node",
            "pkill -f node",
            "pkill -f python",
            "pkill -9 -f 'node server.js'",
            "pkill -u root -f 'node server.js'",
            "pkill -f 'node missing.js'",
            "pkill -f 'node hol-guard.js'",
            "pkill -f hol-guard",
            "pkill -f codex",
            "pkill -f claude",
            "pkill -f omp",
            "killall node",
            "kill -9 1",
        ] {
            let result = fixture.classify(harness, command);
            assert_ne!(result.minimum_action, "allow", "{harness}: {command}");
        }
    }
}
