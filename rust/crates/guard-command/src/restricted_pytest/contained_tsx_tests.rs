//! The command the contained sink builds for a tsx run of Node's test runner.
use super::*;
use serde_json::{json, Value};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::time::{Duration, Instant};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Fixture {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root = env::temp_dir().join(format!("guard-tsx-plan-{}", hex::encode(random)));
    fs::create_dir(&root).unwrap();
    Fixture(root.canonicalize().unwrap())
}

/// A workspace with tsx installed, a Node to run it and two specs to load.
fn workspace(fixture: &Fixture) -> PathBuf {
    let workspace = fixture.0.join("project");
    let bin = workspace.join("bin");
    let dist = workspace.join("node_modules/tsx/dist");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&dist).unwrap();
    fs::create_dir(workspace.join("src")).unwrap();
    fs::write(workspace.join("package.json"), "{}").unwrap();
    fs::write(dist.join("loader.mjs"), "").unwrap();
    fs::write(dist.join("cli.mjs"), "").unwrap();
    fs::write(workspace.join("src/parse.test.ts"), "").unwrap();
    fs::write(workspace.join("src/render.test.ts"), "").unwrap();
    fs::write(bin.join("node"), b"\x7fELFnative-fixture").unwrap();
    fs::set_permissions(bin.join("node"), fs::Permissions::from_mode(0o755)).unwrap();
    workspace
}

fn plan(workspace: &Path, command: &[&str]) -> Value {
    evaluate_with_deadline(
        "prepare_vitest",
        &json!({
            "command":command,"workspace":workspace,"cwd":workspace,"platform":"darwin",
            "backend_executable":"/usr/bin/true","search_path":workspace.join("bin")
        }),
        Instant::now() + Duration::from_secs(5),
    )
}

#[test]
fn the_runner_flags_lead_the_command_and_every_spec_follows_the_loader() {
    let fixture = fixture();
    let workspace = workspace(&fixture);
    let loader = format!(
        "file://{}",
        workspace.join("node_modules/tsx/dist/loader.mjs").display()
    );
    for (line, tail) in [
        (
            vec!["tsx", "--test", "src/parse.test.ts"],
            vec!["--test", "src/parse.test.ts"],
        ),
        (
            vec!["tsx", "--test", "src/parse.test.ts", "src/render.test.ts"],
            vec!["--test", "src/parse.test.ts", "src/render.test.ts"],
        ),
        (
            vec![
                "tsx",
                "--test",
                "--test-only",
                "--test-concurrency=4",
                "src/parse.test.ts",
            ],
            vec![
                "--test",
                "--test-only",
                "--test-concurrency=4",
                "src/parse.test.ts",
            ],
        ),
    ] {
        let reply = plan(&workspace, &line);
        let value = &reply["value"];
        // Node reads the runner flags only ahead of the first file, so the
        // whole command is the executable, the loader, then the flags and
        // every spec in the order the run named them.
        let mut expected = vec![
            value["executable"].as_str().unwrap().to_owned(),
            "--import".to_owned(),
            loader.clone(),
        ];
        expected.extend(tail.iter().map(ToString::to_string));
        assert_eq!(value["command"], json!(expected), "{line:?}");
        assert_eq!(value["profile_version"], json!("vitest-readonly-v1"));
    }
}

#[test]
fn a_spec_that_resolves_outside_the_workspace_never_reaches_the_runner() {
    // The second word is a workspace-shaped test name, so only resolving it
    // shows that the file Node would load lives elsewhere.
    let fixture = fixture();
    let workspace = workspace(&fixture);
    let outside = fixture.0.join("payload.test.ts");
    fs::write(&outside, "").unwrap();
    symlink(&outside, workspace.join("src/linked.test.ts")).unwrap();
    let reply = plan(
        &workspace,
        &["tsx", "--test", "src/parse.test.ts", "src/linked.test.ts"],
    );
    assert_eq!(
        reply["reason_code"],
        json!("vitest_restricted_invalid_command")
    );
}
