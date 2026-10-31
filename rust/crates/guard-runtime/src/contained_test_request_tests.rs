use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Fixture {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).unwrap();
    let root =
        std::env::temp_dir().join(format!("guard-contained-request-{}", hex::encode(random)));
    fs::create_dir(&root).unwrap();
    let root = Fixture(root.canonicalize().unwrap());
    fs::create_dir(root.0.join("project")).unwrap();
    fs::create_dir(root.0.join("temp")).unwrap();
    root
}

fn document(workspace: &Path, payload: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": SCHEMA,
        "workspace": workspace,
        "payload": payload,
    }))
    .unwrap()
}

fn call(workspace: &Path) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": "pytest -q"},
        "cwd": workspace,
    })
}

/// The snapshot written the way the hook writes it, and the reply to reading
/// it back at its own digest.
fn written(fixture: &Fixture, raw: &[u8]) -> (PathBuf, String) {
    let path = crate::hook_direct::contained::request::write_snapshot(&fixture.0.join("temp"), raw)
        .unwrap();
    (path, format!("{:x}", Sha256::digest(raw)))
}

fn read_back(path: &Path, sha256: &str, workspace: &Path) -> Value {
    evaluate(&json!({
        "path": path,
        "sha256": sha256,
        "workspace": workspace,
        "search_path": "/usr/bin",
    }))
}

fn refused(reply: &Value) -> bool {
    reply.get("value").is_none() && reply["reason_code"] == REFUSED
}

#[test]
fn a_snapshot_reads_back_as_the_call_it_carries() {
    let fixture = fixture();
    let workspace = fixture.0.join("project");
    let (path, digest) = written(&fixture, &document(&workspace, call(&workspace)));
    assert_eq!(
        read_back(&path, &digest, &workspace),
        json!({"value": call(&workspace)})
    );
}

#[test]
fn the_snapshot_is_bound_to_its_digest_and_workspace() {
    let fixture = fixture();
    let workspace = fixture.0.join("project");
    let (path, digest) = written(&fixture, &document(&workspace, call(&workspace)));
    let other = "0".repeat(64);
    assert!(refused(&read_back(&path, &other, &workspace)));
    assert!(refused(&read_back(
        &path,
        &digest.to_uppercase(),
        &workspace
    )));
    assert!(refused(&read_back(&path, &digest, &fixture.0)));
}

#[test]
fn only_the_one_document_the_writer_produces_is_read() {
    let fixture = fixture();
    let workspace = fixture.0.join("project");
    let outside = fixture.0.join("temp");
    let mut not_bash = call(&workspace);
    not_bash["tool_name"] = json!("Bash");
    let mut elsewhere = call(&workspace);
    elsewhere["cwd"] = json!(outside);
    let mut no_command = call(&workspace);
    no_command["tool_input"] = json!({"command": ["pytest"]});
    // Read last-wins, this names a bash call; a second reader could see a
    // different tool.
    let duplicated = format!(
        r#"{{"schema":"{SCHEMA}","workspace":"{w}","payload":{{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_name":"bash","tool_input":{{"command":"pytest -q"}}}}}}"#,
        w = workspace.display()
    );
    for raw in [
        document(&workspace, not_bash),
        document(&workspace, elsewhere),
        document(&workspace, no_command),
        duplicated.into_bytes(),
        serde_json::to_vec(&json!({"schema": SCHEMA, "workspace": workspace,
            "payload": call(&workspace), "extra": 1}))
        .unwrap(),
    ] {
        let (path, digest) = written(&fixture, &raw);
        assert!(refused(&read_back(&path, &digest, &workspace)));
    }
}

#[test]
fn a_snapshot_left_readable_or_linked_is_refused() {
    let fixture = fixture();
    let workspace = fixture.0.join("project");
    let raw = document(&workspace, call(&workspace));
    let (path, digest) = written(&fixture, &raw);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(refused(&read_back(&path, &digest, &workspace)));

    let (path, digest) = written(&fixture, &raw);
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(refused(&read_back(&path, &digest, &workspace)));

    let (path, digest) = written(&fixture, &raw);
    let target = fixture.0.join("target.json");
    fs::rename(&path, &target).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(refused(&read_back(&path, &digest, &workspace)));
}

#[test]
fn a_request_outside_a_snapshot_directory_is_refused_unread() {
    let fixture = fixture();
    let workspace = fixture.0.join("project");
    let raw = document(&workspace, call(&workspace));
    let (path, digest) = written(&fixture, &raw);
    let renamed = fixture.0.join("temp/elsewhere");
    fs::rename(path.parent().unwrap(), &renamed).unwrap();
    assert!(refused(&read_back(
        &renamed.join(FILE_NAME),
        &digest,
        &workspace
    )));
    let other_name = renamed.join("other.json");
    fs::rename(renamed.join(FILE_NAME), &other_name).unwrap();
    assert!(refused(&read_back(&other_name, &digest, &workspace)));
}
