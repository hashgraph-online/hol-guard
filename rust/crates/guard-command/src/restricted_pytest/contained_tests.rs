use super::*;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};

fn expand(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => {
            let ancestors = Path::new(root)
                .ancestors()
                .skip(1)
                .filter(|p| *p != Path::new("/"))
                .map(|p| {
                    format!(
                        "(literal {})",
                        super::credentials::seatbelt_string(&p.to_string_lossy())
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            json!(text
                .replace("$FIXTURE_ANCESTORS", &ancestors)
                .replace("$ROOT", root))
        }
        Value::Array(items) => json!(items.iter().map(|v| expand(v, root)).collect::<Vec<_>>()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(k, v)| (k.replace("$ROOT", root), expand(v, root)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

struct Fixture(PathBuf);

#[test]
fn per_request_home_selects_nvm_and_preserves_home_root_refusal() {
    let fixture = fixture("guard-caller-home");
    let home = fixture.0.join("caller-home");
    let node = home.join(".nvm/versions/node/v20.1.2/bin/node");
    let workspace = fixture.0.join("project");
    fs::create_dir_all(node.parent().unwrap()).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("package.json"), "{}").unwrap();
    fs::write(home.join("package.json"), "{}").unwrap();
    fs::write(&node, b"\x7fELFnative-fixture").unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
    let request = json!({"path":node,"workspace":workspace,"home":home});
    assert_eq!(evaluate("approved_node", &request), json!({"value":true}));
    let mut wrong_home = request;
    wrong_home["home"] = json!(workspace);
    assert_eq!(
        evaluate("approved_node", &wrong_home),
        json!({"value":false})
    );
    let mut launch = json!({"command":[node,"--test"],"workspace":workspace,"cwd":workspace,
        "home":home,"platform":"darwin","backend_executable":"/usr/bin/true","search_path":""});
    assert_eq!(
        evaluate("prepare_node", &launch)["value"]["executable"],
        json!(node)
    );
    launch["workspace"] = json!(home);
    launch["cwd"] = json!(home);
    assert_eq!(
        evaluate("prepare_node", &launch)["reason_code"],
        PYTEST_INVALID_WORKSPACE_REASON_CODE
    );
    launch["command"] = json!(["python3", "-c", "print(1)"]);
    assert_eq!(
        evaluate("prepare_inline", &launch)["reason_code"],
        PYTEST_INVALID_WORKSPACE_REASON_CODE
    );
}

#[test]
fn passwd_home_stays_sensitive_when_the_caller_home_differs() {
    let fixture = fixture("guard-passwd-home");
    let caller = fixture.0.join("caller-home");
    fs::create_dir_all(&caller).unwrap();
    let host = super::paths::host_home_directory().expect("account home");
    let launch = json!({
        "command": ["python3", "-c", "print(1)"],
        "workspace": host,
        "cwd": host,
        "home": caller,
        "platform": "darwin",
        "backend_executable": "/usr/bin/true",
        "search_path": ""
    });
    let result = evaluate("prepare_inline", &launch);
    assert_eq!(result["reason_code"], PYTEST_INVALID_WORKSPACE_REASON_CODE);
    assert!(
        result["message"].as_str().unwrap_or("").contains("home"),
        "{result}"
    );
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(prefix: &str) -> Fixture {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root = env::temp_dir().join(format!("{prefix}-{}", hex::encode(random)));
    fs::create_dir(&root).unwrap();
    Fixture(root.canonicalize().unwrap())
}

#[test]
fn recorded_original_contained_execution_outcomes() {
    let fixture = fixture("guard-contained-parity");
    let workspace = fixture.0.join("project");
    fs::create_dir_all(workspace.join("bin")).unwrap();
    fs::create_dir(workspace.join("tests")).unwrap();
    fs::write(workspace.join("package.json"), "{}").unwrap();
    let manifest = workspace.join("node_modules/vitest/package.json");
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    fs::write(manifest.with_file_name("vitest.mjs"), "").unwrap();
    let node = workspace.join("bin/node");
    fs::write(&node, b"\xcf\xfa\xed\xfenative-fixture").unwrap();
    let vectors: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/contained_execution_parity.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        if case["operation"] == "process_ceiling_snapshot" {
            continue;
        }
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&manifest, r#"{"name":"vitest","version":"4.0.0"}"#).unwrap();
        let mut input = expand(&case["input"], fixture.0.to_str().unwrap());
        if let Some(version) = input.as_object_mut().unwrap().remove("fixture_version") {
            fs::write(
                &manifest,
                json!({"name":"vitest","version":version}).to_string(),
            )
            .unwrap();
        }
        if let Some(mode) = input.as_object_mut().unwrap().remove("fixture_mode") {
            fs::set_permissions(
                &node,
                fs::Permissions::from_mode(mode.as_u64().unwrap() as u32),
            )
            .unwrap();
        }
        if let Some(files) = case.get("fixture_files") {
            for (path, bytes) in expand(files, fixture.0.to_str().unwrap())
                .as_object()
                .unwrap()
            {
                fs::write(path, hex::decode(bytes.as_str().unwrap()).unwrap()).unwrap();
            }
        }
        let operation = case["operation"].as_str().unwrap();
        let mut expected = expand(&case["expected"], fixture.0.to_str().unwrap());
        let actual = if let Some(grants) = case.get("system_grants") {
            super::profiles::replay_profile(&input, &expand(grants, fixture.0.to_str().unwrap()))
        } else {
            evaluate_with_deadline(operation, &input, Instant::now() + Duration::from_secs(10))
        };
        if let Some(records) = expected.get_mut("value").and_then(Value::as_array_mut) {
            for record in records {
                if record.get("identity") == Some(&json!("$IDENTITY")) {
                    let path = record["path"].as_str().unwrap();
                    let m = fs::metadata(path).unwrap();
                    record["identity"] = json!([
                        m.dev(),
                        m.ino(),
                        m.len(),
                        m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
                        m.mode()
                    ]);
                }
            }
        }
        assert_eq!(actual, expected, "operation={operation}, input={input}");
    }
}

#[test]
fn mapping_deadline_and_packed_input_fail_closed() {
    let expired = Instant::now() - Duration::from_secs(1);
    let result = evaluate_with_deadline("mapping_evidence", &json!({}), expired);
    assert_eq!(result["reason_code"], "linux_mapping_unavailable");
    let malformed = evaluate_with_deadline(
        "mapping_evidence",
        &json!({"packed_json_gzip_v1":"invalid","decoded_bytes":1}),
        Instant::now() + Duration::from_secs(1),
    );
    assert_eq!(malformed["reason_code"], "linux_mapping_unavailable");
}

#[test]
fn relative_vitest_entry_uses_request_cwd_without_changing_resident_cwd() {
    let fixture = fixture("guard-vitest-relative");
    let workspace = fixture.0.join("project");
    let bin = workspace.join("bin");
    let entry = workspace.join("node_modules/vitest/vitest.mjs");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(entry.parent().unwrap()).unwrap();
    fs::write(workspace.join("package.json"), "{}").unwrap();
    fs::write(&entry, "").unwrap();
    fs::write(bin.join("node"), b"\x7fELFnative-fixture").unwrap();
    fs::set_permissions(bin.join("node"), fs::Permissions::from_mode(0o755)).unwrap();
    let before = env::current_dir().unwrap();
    let reply = evaluate_with_deadline(
        "prepare_vitest",
        &json!({
            "command":["node","./node_modules/vitest/vitest.mjs","run"],
            "workspace":workspace,"cwd":workspace,"platform":"darwin",
            "backend_executable":"/usr/bin/true","search_path":bin
        }),
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(reply["value"]["command"][1], json!(entry));
    assert_eq!(env::current_dir().unwrap(), before);
}

#[test]
fn large_ordinary_file_index_keeps_the_mapping_deadline_for_image_inspection() {
    let input = json!({"images":[],"read_files":(0..100000).map(|i|
        format!("/guard-fixture/workspace/a/b/c/d/e/f/ordinary-{i}.txt")).collect::<Vec<_>>(),
        "runtime_roots":["/guard-fixture/runtime"],"workspace":"/guard-fixture/workspace"});
    let result = evaluate_with_deadline(
        "mapping_evidence",
        &input,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(result, json!({"value":[]}));
}

#[test]
fn mapping_snapshot_is_descriptor_bound_and_can_exceed_an_ipc_frame() {
    use sha2::{Digest, Sha256};
    let fixture = fixture("hol-guard-mapping-parity");
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o700)).unwrap();
    let path = fixture.0.join("mapping-index.json");
    let payload = json!({"read_files":(0..100000).map(|i|format!("/guard-fixture/library/module-{i}.so")).collect::<Vec<_>>()});
    let raw = serde_json::to_vec(&payload).unwrap();
    assert!(raw.len() > 2 * 1024 * 1024);
    fs::write(&path, &raw).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut input = json!({"mapping_snapshot":path,"decoded_bytes":raw.len(),"sha256":format!("{:x}",Sha256::digest(&raw))});
    let deadline = Instant::now() + Duration::from_secs(10);
    assert_eq!(
        super::mapping_snapshot::read(&input, deadline).unwrap(),
        payload
    );
    let records = json!((0..1024)
        .map(
            |i| json!({"path":format!("/workspace/{}-{i}","module-".repeat(430)),
        "identity":[1,i,1,1,0o100500],"sha256":"0".repeat(64)})
        )
        .collect::<Vec<_>>());
    let result = super::mapping_snapshot::write(&input, &records, deadline).unwrap();
    assert!(result["decoded_bytes"].as_u64().unwrap() > 2 * 1024 * 1024);
    assert!(serde_json::to_vec(&result).unwrap().len() < 1024);
    let output = fixture.0.join("mapping-result.json");
    assert_eq!(fs::metadata(&output).unwrap().mode() & 0o077, 0);
    let bytes = fs::read(&output).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        result["sha256"].as_str().unwrap()
    );
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), records);
    input["sha256"] = json!("0".repeat(64));
    assert!(super::mapping_snapshot::read(&input, deadline).is_err());
    input["sha256"] = json!(format!("{:x}", Sha256::digest(&raw)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(super::mapping_snapshot::read(&input, deadline).is_err());
}

#[test]
fn expired_mapping_deadline_stops_before_an_unreadable_snapshot() {
    let expired = Instant::now() - Duration::from_secs(1);
    let missing = json!({
        "mapping_snapshot": "/tmp/hol-guard-mapping-missing/mapping-index.json",
        "decoded_bytes": 2,
        "sha256": "ab".repeat(32),
    });
    let stopped = evaluate_with_deadline("mapping_evidence", &missing, expired);
    assert_eq!(
        stopped["message"],
        "Linux executable mapping inspection deadline exceeded."
    );
    let inspected = evaluate_with_deadline(
        "mapping_evidence",
        &missing,
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(inspected["message"], "Invalid executable mapping snapshot.");
}

#[test]
fn nvm_node_under_process_home_stays_approved_when_passwd_home_differs() {
    const CHILD: &str = "HOL_GUARD_NVM_HOME_CHILD";
    if env::var_os(CHILD).is_none() {
        let fixture = fixture("hol-guard-nvm-home");
        let status = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "restricted_pytest::contained_tests::nvm_node_under_process_home_stays_approved_when_passwd_home_differs",
                "--test-threads=1",
            ])
            .env("HOME", &fixture.0)
            .env(CHILD, "1")
            .env("HOL_GUARD_NVM_FIXTURE", &fixture.0)
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let root = PathBuf::from(env::var_os("HOL_GUARD_NVM_FIXTURE").unwrap());
    let executable = root.join(".nvm/versions/node/v20.11.0/bin/node");
    fs::create_dir_all(executable.parent().unwrap()).unwrap();
    fs::write(&executable, b"\x7fELF").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let workspace = root.join("project");
    fs::create_dir_all(&workspace).unwrap();
    let outside = root.join("other/bin/node");
    fs::create_dir_all(outside.parent().unwrap()).unwrap();
    fs::write(&outside, b"\x7fELF").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o755)).unwrap();
    let approved = evaluate(
        "approved_node",
        &json!({"path": executable, "workspace": workspace}),
    );
    let rejected = evaluate(
        "approved_node",
        &json!({"path": outside, "workspace": workspace}),
    );
    assert_eq!(approved["value"], json!(true));
    assert_eq!(rejected["value"], json!(false));
}

#[test]
fn profile_preserves_denials_and_readonly_workspace() {
    let input = json!({"profile_version":"vitest-readonly-v1","workspace":"/guard-project","cwd":"/guard-project",
        "private_root":"/guard-private","allowed_executables":["/usr/bin/node"],"command":["/usr/bin/node"]});
    let result = evaluate("macos_profile", &input);
    let profile = result["value"].as_str().unwrap();
    assert!(profile.starts_with("(version 1)\n(deny default)\n(deny file-link)"));
    assert!(profile.contains("(allow process-exec (literal \"/usr/bin/node\"))"));
    assert!(profile.contains("(deny file-write* (literal \"/usr/bin/node\"))"));
    assert!(profile
        .contains("(allow file-write* (subpath \"/guard-private\") (literal \"/dev/null\"))"));
    for denial in super::credentials::denials(true) {
        assert!(profile.contains(&denial));
    }
}

// A fresh project with only source and tests is still a pytest root.
#[test]
fn root_test_modules_mark_a_project_but_not_a_home_or_a_link() {
    let fixture = fixture("guard-test-module-root");
    let resolve = |path: &Path| super::validation::resolve_workspace_with_home(path, None);
    for (name, marks) in [
        ("test_cli.py", true),
        ("cli_test.py", true),
        ("conftest.py", true),
        ("test_.py", false),
        ("cli.py", false),
        ("test_cli.txt", false),
    ] {
        let workspace = fixture.0.join(format!("project-{name}"));
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join(name), "").unwrap();
        assert_eq!(resolve(&workspace).is_ok(), marks, "{name}");
    }
    let linked = fixture.0.join("linked");
    fs::create_dir(&linked).unwrap();
    std::os::unix::fs::symlink(
        fixture.0.join("project-test_cli.py/test_cli.py"),
        linked.join("test_cli.py"),
    )
    .unwrap();
    assert!(resolve(&linked).is_err());

    let home = fixture.0.join("caller-home");
    fs::create_dir(&home).unwrap();
    fs::write(home.join("test_cli.py"), "").unwrap();
    let refused = super::validation::resolve_workspace_with_home(&home, Some(&home));
    assert!(refused.is_err());
}

#[test]
fn bun_inline_eval_uses_the_node_eval_profile_with_an_installer_image() {
    let fixture = fixture("guard-bun-eval");
    let home = fixture.0.join("caller-home");
    let bun = home.join(".bun/bin/bun");
    let workspace = fixture.0.join("project");
    fs::create_dir_all(bun.parent().unwrap()).unwrap();
    fs::create_dir(&workspace).unwrap();
    fs::write(workspace.join("package.json"), "{}").unwrap();
    fs::write(&bun, b"\x7fELFnative-fixture").unwrap();
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o755)).unwrap();
    let mut launch = json!({"command":[bun,"-e","console.log(1)"],"workspace":workspace,
        "cwd":workspace,"home":home,"platform":"darwin","backend_executable":"/usr/bin/true",
        "search_path":""});
    let result = evaluate("prepare_inline", &launch);
    let plan = &result["value"];
    assert_eq!(plan["profile_version"], "node-eval-readonly-v1", "{plan}");
    assert_eq!(plan["command"], json!([bun, "-e", "console.log(1)"]));
    assert_eq!(
        plan["denied_capabilities"],
        json!([
            "host-home-read",
            "host-secret-environment",
            "network",
            "docker-socket",
            "workspace-write",
            "workspace-credential-read",
            "unapproved-process-exec",
            "privileged-operation"
        ])
    );
    launch["command"] = json!([bun, "--print", "1"]);
    assert_eq!(
        evaluate("prepare_inline", &launch)["value"]["command"],
        json!([bun, "--print", "1"])
    );
    // Another home's installer, a repository copy, a writable or script image.
    let invalid = |launch: &Value| {
        assert_eq!(
            evaluate("prepare_inline", launch)["reason_code"],
            "inline_eval_invalid_command",
            "{launch}"
        );
    };
    let other = fixture.0.join("other-home");
    fs::create_dir(&other).unwrap();
    launch["home"] = json!(other);
    invalid(&launch);
    launch["home"] = json!(home);
    let local = workspace.join("bun");
    fs::copy(&bun, &local).unwrap();
    launch["command"] = json!([local, "-e", "1"]);
    invalid(&launch);
    launch["command"] = json!([bun, "-e", "1"]);
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o775)).unwrap();
    invalid(&launch);
    fs::write(&bun, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&bun, fs::Permissions::from_mode(0o755)).unwrap();
    invalid(&launch);
    launch["command"] = json!([bun, "run", "-e", "1"]);
    invalid(&launch);
}
