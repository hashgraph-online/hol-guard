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
