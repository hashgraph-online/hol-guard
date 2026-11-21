//! Public policy parity from pinned Python bodies and explicit fixture service facts.
use super::parity_tests::Fixture;
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Authority {
    environment: BTreeMap<String, String>,
    trusted: Vec<String>,
    digest: String,
    expired: bool,
}
impl DirectToolAuthority for Authority {
    fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }
    fn trusted_command(&self, command: &str, _: &Path, _: &Path) -> bool {
        self.trusted.iter().any(|name| name == command)
    }
    fn trusted_path(&self, _: &Path, _: &Path) -> bool {
        false
    }
    fn executable_file(&self, path: &Path) -> bool {
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    fn temp_directory(&self) -> &Path {
        Path::new("/tmp")
    }
    fn within_budget(&self) -> bool {
        !self.expired
    }
    fn typescript_package_digest(&self, version: &str, integrity: &str) -> Option<&str> {
        // Test-only synthetic root, identical to the legacy fixture. No request
        // contract accepts package digests or trust overrides.
        (version == "5.9.3" && integrity == "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw==").then_some(self.digest.as_str())
    }
}

fn prepare(root: &Path, fixture: &Value) {
    fs::create_dir_all(root.join("home/caller")).unwrap();
    for file in fixture["files"].as_array().unwrap() {
        let path = root.join(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            hex::decode(file["bytes_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        if file["executable"] == true {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    for file in fixture["symlinks"].as_array().unwrap() {
        let path = root.join(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(file["target"].as_str().unwrap(), path).unwrap();
    }
}

#[test]
fn direct_tool_recorded_python_public_parity() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/direct-tool-python.v1.json"
    ))
    .unwrap();
    let mut mismatches = Vec::new();
    let mut positives = 0;
    for (index, case) in fixture["public_cases"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let root = Fixture::new();
        prepare(&root.0, &fixture["public_fixture"]);
        for mutation in case["mutations"].as_array().unwrap() {
            let path = root.0.join(mutation["path"].as_str().unwrap());
            match mutation["kind"].as_str().unwrap() {
                "remove" => fs::remove_file(path).unwrap(),
                "write" => fs::write(
                    path,
                    hex::decode(mutation["bytes_hex"].as_str().unwrap()).unwrap(),
                )
                .unwrap(),
                kind => panic!("unknown fixture action {kind}"),
            }
        }
        let home = root.0.join("home");
        let cwd = home.join("caller");
        let workspace = home.join("subject");
        let command = case["command"]
            .as_str()
            .unwrap()
            .replace("{workspace}", &workspace.to_string_lossy())
            .replace(
                "{runner}",
                &workspace
                    .join("node_modules/vitest/vitest.mjs")
                    .to_string_lossy(),
            );
        let mut authority = Authority {
            environment: serde_json::from_value(case["environment"].clone()).unwrap(),
            trusted: serde_json::from_value(case["trusted_commands"].clone()).unwrap(),
            digest: case["trusted_tree_sha256"].as_str().unwrap().to_owned(),
            expired: false,
        };
        let check = |authority: &Authority| match case["tool"].as_str().unwrap() {
            "vitest" => {
                direct_local_vitest_execution_context(&command, Some(&cwd), &home, authority)
            }
            "typescript" => {
                direct_local_typescript_execution_context(&command, Some(&cwd), &home, authority)
            }
            tool => panic!("unknown tool {tool}"),
        };
        let result = check(&authority);
        if result.is_some() != case["expected"].as_bool().unwrap() {
            mismatches.push(format!(
                "case {index}: expected={}, native={}, command={}",
                case["expected"],
                result.is_some(),
                case["command"]
            ));
        }
        if let Some(context) = result {
            positives += 1;
            assert!(context.complete);
            assert_eq!(context.command_text, command);
            assert_eq!(context.workspace_root.as_deref(), Some(workspace.as_path()));
            authority.expired = true;
            assert!(
                check(&authority).is_none(),
                "expired request cannot keep an accepted context"
            );
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    assert!(positives >= 10);
}

/// The workspace's own compiler reaches the same route spelled as a path.
///
/// `npx tsc` and `./node_modules/.bin/tsc` run the one binary the binding
/// check pins to the workspace's `typescript` package, so a project that
/// writes the path out rather than letting npx resolve it asks for the same
/// no-emit run. The reporting options tsc reads an optional `true` or `false`
/// after travel with it, because none of them turns emit on.
#[test]
fn a_local_typescript_compiler_runs_under_every_spelling_of_its_own_binary() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/direct-tool-python.v1.json"
    ))
    .unwrap();
    const ADMITTED: &[&str] = &[
        "cd {workspace} && ./node_modules/.bin/tsc --noEmit src/index.ts 2>&1 | grep -v \"npm warn\" | head -8 ; echo TSC_DONE",
        "cd {workspace} && node_modules/.bin/tsc --noEmit 2>&1",
        "cd {workspace} && ./node_modules/.bin/tsc --noEmit --project tsconfig.json --pretty=false 2>&1",
        "cd {workspace} && ./node_modules/.bin/tsc --noEmit 2>&1 | grep -E \"src/index\\.ts\" || echo NO_ERRORS_IN_TOUCHED_FILES",
        "cd {workspace} && npx tsc --noEmit --pretty false 2>&1",
        "cd {workspace} && npx tsc --noEmit --listFilesOnly --noErrorTruncation 2>&1",
    ];
    const REFUSED: &[&str] = &[
        // A compiler option's own value still turns the run around.
        "cd {workspace} && ./node_modules/.bin/tsc --noEmit false 2>&1",
        "cd {workspace} && ./node_modules/.bin/tsc --emitDeclarationOnly --noEmit 2>&1",
        // The word after a reporting option is its boolean or a file the
        // workspace holds, and `maybe` is neither.
        "cd {workspace} && ./node_modules/.bin/tsc --noEmit --pretty maybe 2>&1",
        "cd {workspace} && npx tsc --noEmit --pretty=yes 2>&1",
        // The package's entrypoint is not the link the binding check pins.
        "cd {workspace} && ./node_modules/typescript/bin/tsc --noEmit 2>&1",
    ];
    for (command, expected) in ADMITTED
        .iter()
        .map(|command| (command, true))
        .chain(REFUSED.iter().map(|command| (command, false)))
    {
        let root = Fixture::new();
        prepare(&root.0, &fixture["public_fixture"]);
        let home = root.0.join("home");
        let cwd = home.join("caller");
        let workspace = home.join("subject");
        let command = command.replace("{workspace}", &workspace.to_string_lossy());
        let authority = Authority {
            environment: BTreeMap::new(),
            trusted: ["grep", "head", "node", "npx", "tail"]
                .iter()
                .map(|name| (*name).to_owned())
                .collect(),
            digest: "c3b1504344b1a42e5d174df8a2ae16c7892d03668db6570ef6afe4248b96e0b8".to_owned(),
            expired: false,
        };
        assert_eq!(
            direct_local_typescript_execution_context(&command, Some(&cwd), &home, &authority)
                .is_some(),
            expected,
            "{command}"
        );
    }
}

/// A path to the workspace's own compiler needs no trusted `npx`.
///
/// npx is on the line only in the spelling that asks it to resolve the
/// compiler, so a host whose `npx` is not a trusted program still runs the
/// link the binding check pins, and the npx spelling on that same host does
/// not.
#[test]
fn a_path_spelled_typescript_run_does_not_rest_on_npx() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/direct-tool-python.v1.json"
    ))
    .unwrap();
    for (command, expected) in [
        (
            "cd {workspace} && ./node_modules/.bin/tsc --noEmit 2>&1",
            true,
        ),
        ("cd {workspace} && npx tsc --noEmit 2>&1", false),
    ] {
        let root = Fixture::new();
        prepare(&root.0, &fixture["public_fixture"]);
        let home = root.0.join("home");
        let cwd = home.join("caller");
        let workspace = home.join("subject");
        let command = command.replace("{workspace}", &workspace.to_string_lossy());
        let authority = Authority {
            environment: BTreeMap::new(),
            trusted: vec!["node".to_owned()],
            digest: "c3b1504344b1a42e5d174df8a2ae16c7892d03668db6570ef6afe4248b96e0b8".to_owned(),
            expired: false,
        };
        assert_eq!(
            direct_local_typescript_execution_context(&command, Some(&cwd), &home, &authority)
                .is_some(),
            expected,
            "{command}"
        );
    }
}
