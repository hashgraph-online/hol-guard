//! Frozen leaf verdicts from the pinned Python implementation, with no oracle.

use super::*;
use serde_json::json;
use std::env;
use std::io::Write;

#[derive(Default)]
struct TestAuthority {
    environment: BTreeMap<String, String>,
}
impl DirectToolAuthority for TestAuthority {
    fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }
    fn trusted_command(&self, _: &str, _: &Path, _: &Path) -> bool {
        false
    }
    fn trusted_path(&self, _: &Path, _: &Path) -> bool {
        false
    }
    fn executable_file(&self, path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    fn temp_directory(&self) -> &Path {
        Path::new("/tmp")
    }
    fn within_budget(&self) -> bool {
        true
    }
}

pub(super) struct Fixture(pub(super) PathBuf);
impl Fixture {
    pub(super) fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let root = env::temp_dir().join(format!("guard-direct-tool-test-{}", hex::encode(nonce)));
        fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn sparse(path: &Path, size: u64) {
    fs::File::create_new(path).unwrap().set_len(size).unwrap();
}

fn input_file(root: &Path, case: &Value) -> PathBuf {
    let path = root.join(case["name"].as_str().unwrap());
    match case["kind"].as_str().unwrap_or("file") {
        "missing" => {}
        "directory" => fs::create_dir(&path).unwrap(),
        "symlink" => {
            let target = root.join("synthetic-target");
            fs::write(&target, "{}").unwrap();
            std::os::unix::fs::symlink(target, &path).unwrap();
        }
        "oversize" => sparse(&path, 16 * 1024 * 1024 + 1),
        "invalid_utf8" => fs::write(&path, [0xff]).unwrap(),
        "file" => fs::write(
            &path,
            hex::decode(case["bytes_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
        kind => panic!("unknown fixture kind {kind}"),
    }
    path
}

fn tree(root: &Path, case: &Value) -> PathBuf {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    for file in case["files"].as_array().unwrap() {
        let path = workspace.join(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            hex::decode(file["bytes_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    }
    match case["kind"].as_str().unwrap_or("tree") {
        "root_symlink" => {
            let link = root.join("link");
            std::os::unix::fs::symlink(workspace, &link).unwrap();
            return link;
        }
        "file_symlink" | "dir_symlink" => {
            let outside = root.join("outside");
            if case["kind"] == "dir_symlink" {
                fs::create_dir(&outside).unwrap();
            } else {
                fs::write(&outside, "synthetic").unwrap();
            }
            std::os::unix::fs::symlink(outside, workspace.join("link")).unwrap();
        }
        "oversize" => sparse(&workspace.join("large"), 128 * 1024 * 1024 + 1),
        "tree" => {}
        kind => panic!("unknown fixture kind {kind}"),
    }
    workspace
}

fn target(root: &Path, case: &Value) -> Value {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).unwrap();
    for name in ["a.test.ts", "a.TEST.ts", "nested/a.spec.ts"] {
        let path = workspace.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = fs::File::create(path).unwrap();
        file.write_all(b"synthetic test").unwrap();
    }
    let outside = root.join("outside.test.ts");
    fs::write(&outside, "synthetic outside").unwrap();
    std::os::unix::fs::symlink(workspace.join("a.test.ts"), workspace.join("link.test.ts"))
        .unwrap();
    std::os::unix::fs::symlink(outside, workspace.join("nested/link.test.ts")).unwrap();
    json!(contained_test_target(
        case["value"].as_str().unwrap(),
        &workspace
    ))
}

#[test]
fn direct_tool_recorded_python_leaf_parity() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/direct-tool-python.v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["schema"], "hol-guard.direct-tool-python.v1");
    let mut mismatches = Vec::new();
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let root = Fixture::new();
        let check = case["check"].as_str().unwrap();
        let actual = match check {
            "semver" => json!(semver_spec_matches(
                case["specifier"].as_str().unwrap(),
                case["version"].as_str().unwrap()
            )),
            "heap" => json!(safe_node_heap_assignment(case["value"].as_str().unwrap())),
            "dynamics" => json!(has_shell_dynamics(case["value"].as_str().unwrap())),
            "bunfig" => json!(bunfig_is_install_only(&input_file(&root.0, case))),
            "package_json" => json!(read_package_json(&input_file(&root.0, case))),
            "bun_identity" => json!(locked_bun_package_identity(
                &input_file(&root.0, case),
                "typescript"
            )),
            "locked_version" => json!(locked_package_version(&input_file(&root.0, case), "vitest")),
            "tree" => json!(package_tree_digest(
                &tree(&root.0, case),
                &TestAuthority::default()
            )),
            "target" => target(&root.0, case),
            _ => panic!("unknown check {check}"),
        };
        if actual != case["expected"] {
            mismatches.push(format!(
                "case {index} {check}: native={actual}, recorded={}",
                case["expected"]
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
