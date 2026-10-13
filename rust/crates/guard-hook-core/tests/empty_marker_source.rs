use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use sha2::{Digest, Sha256};

struct TestRoot(std::path::PathBuf);

impl TestRoot {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut attempt = 0;
        let root = loop {
            let root = std::env::temp_dir().join(format!(
                "guard-empty-marker-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match std::fs::create_dir(&root) {
                Ok(()) => break root,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => attempt += 1,
                Err(error) => panic!("failed to create test root: {error}"),
            }
        };
        Self(root.canonicalize().unwrap())
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(home: &std::path::Path, path: &std::path::Path, output: &str) -> NativeHookRequestV1 {
    let path = path.to_string_lossy();
    let path = path.as_ref();
    build(home, path, output)
}

fn build(home: &std::path::Path, path: &str, output: &str) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("r".into()),
        harness: "omp".into(),
        event_name: "PostToolUse".into(),
        payload: json!({
            "tool_name": "read", "tool_input": {"path": path},
            "tool_response": output,
            "guard_source_ref": {"version": 1, "kind": "source_file",
                "path": path, "tool_input_path": path,
                "output_sha256": format!("{:x}", Sha256::digest(output.as_bytes())),
                "output_chars": output.chars().count()},
            "tool_response_summary": {"kind":"text","text_excerpt":output,"excerpt_chars":output.len(),
                "output_chars":output.chars().count(),
                "output_sha256": format!("{:x}", Sha256::digest(output.as_bytes())),"excerpt_truncated":false}
        }),
        cwd: Some(home.join("project").to_string_lossy().into()),
        home_dir: home.to_string_lossy().into(),
        guard_home: home.join("guard").to_string_lossy().into(),
        source_ref_external_allowed: true,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

fn fixture() -> TestRoot {
    let root = TestRoot::new();
    let home = root.path();
    std::fs::create_dir_all(home.join("project/.git")).unwrap();
    std::fs::create_dir_all(home.join("other-project/.git")).unwrap();
    std::fs::create_dir_all(home.join("plain")).unwrap();
    root
}

#[test]
fn empty_marker_reads_in_work_trees_are_reviewed_and_allowed() {
    let root = fixture();
    let home = root.path();
    for marker in [
        "other-project/.keep",
        "project/.keep",
        "project/src/.gitkeep",
    ] {
        let path = home.join(marker);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();
        let decision = review_post_tool(&request(home, &path, ""));
        assert_eq!(
            decision.decision, "allow",
            "{marker}: {}",
            decision.reason_code
        );
    }
}

#[test]
fn hidden_reads_that_are_not_empty_work_tree_markers_stay_denied() {
    let root = fixture();
    let home = root.path();
    for (name, contents) in [
        ("project/.keep", "x\n"),
        ("project/.env", ""),
        ("other-project/.env.local", ""),
        ("project/.npmrc", ""),
        ("plain/.keep", ""),
    ] {
        let path = home.join(name);
        std::fs::write(&path, contents).unwrap();
        let decision = review_post_tool(&request(home, &path, contents));
        assert_eq!(
            decision.decision, "deny",
            "{name}: {}",
            decision.reason_code
        );
    }
}
