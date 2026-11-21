use std::fs;
#[cfg(unix)]
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::transition_files::dispatch;

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const INVALID: &str = "publication_inverse_native_binding_invalid";

fn ask(op: &str, extra: Value) -> Value {
    let mut request = json!({
        "op": op,
        "home": std::env::temp_dir().join("inverse-pinned-home").to_string_lossy(),
    });
    request
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap());
    dispatch(&request).unwrap()
}

fn runtime(path: &str, size: u64, mtime_ns: i64, sha256: &str) -> Value {
    json!({"path": path, "size": size, "mtime_ns": mtime_ns, "sha256": sha256})
}

#[test]
fn a_binding_names_a_runtime_and_a_workspace_or_neither() {
    let workspace = std::env::temp_dir();
    let relative = runtime("runtime", 1, 1, DIGEST);
    for (native, work) in [
        (runtime("/", 1, 1, DIGEST), Value::Null),
        (Value::Null, json!(workspace.to_string_lossy())),
        (relative, json!(workspace.to_string_lossy())),
        (
            runtime("/bin/sh", 0, 1, DIGEST),
            json!(workspace.to_string_lossy()),
        ),
        (
            runtime("/bin/sh", 1, 1, &DIGEST.to_uppercase()),
            json!(workspace.to_string_lossy()),
        ),
        (
            runtime("/bin/sh", 1, 1, "abc"),
            json!(workspace.to_string_lossy()),
        ),
        (runtime("/bin/sh", 1, 1, DIGEST), json!("relative")),
        (
            runtime("/bin/sh", 1, 1, DIGEST),
            json!(workspace.join("absent").to_string_lossy()),
        ),
    ] {
        let answer = ask(
            "publication_inverse_bind",
            json!({"dependencies": [], "native_runtime": native, "verification_workspace": work}),
        );
        assert_eq!(answer["error"]["transition"], INVALID, "{native} {work}");
    }
}

#[test]
fn an_absent_runtime_is_refused_by_name() {
    let workspace = fs::canonicalize(std::env::temp_dir()).unwrap();
    let missing = workspace.join("inverse-pinned-absent-runtime");
    let answer = ask(
        "publication_inverse_bind",
        json!({
            "dependencies": [],
            "native_runtime": runtime(&missing.to_string_lossy(), 1, 1, DIGEST),
            "verification_workspace": workspace.to_string_lossy(),
        }),
    );
    assert_eq!(answer["error"]["integrity"], "codex_hook_artifact_missing");
}

#[cfg(unix)]
struct Bound {
    root: PathBuf,
    path: PathBuf,
}

#[cfg(unix)]
impl Bound {
    fn new(mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "inverse-pinned-{}-{}",
                std::process::id(),
                crate::unique_nanos::unique_nanos()
            ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("runtime");
        fs::write(&path, b"runtime bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        Self { root, path }
    }

    fn mtime_ns(&self) -> i64 {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&self.path).unwrap();
        meta.mtime() * 1_000_000_000 + meta.mtime_nsec()
    }

    fn bind(&self, dependencies: Value, mtime_ns: i64) -> Value {
        ask(
            "publication_inverse_bind",
            json!({
                "dependencies": dependencies,
                "native_runtime": runtime(&self.path.to_string_lossy(), 13, mtime_ns, DIGEST),
                "verification_workspace": self.root.to_string_lossy(),
            }),
        )
    }
}

#[cfg(unix)]
impl Drop for Bound {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
#[test]
fn a_bound_runtime_is_pinned_by_its_digest_and_merges_once() {
    let bound = Bound::new(0o700);
    let answer = bound.bind(json!([]), bound.mtime_ns());
    let files = answer["value"]["files"].as_array().unwrap().clone();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["path"], json!(bound.path.to_string_lossy()));
    assert_eq!(files[0]["expected_digest"], DIGEST);
    assert_eq!(files[0]["before_mode"], 0o700);
    assert_eq!(files[0]["artifact_identity"]["role"], "artifact");
    assert_eq!(files[0]["artifact_identity"]["size"], 13);
    let again = bound.bind(Value::Array(files.clone()), bound.mtime_ns());
    assert_eq!(again["value"]["files"], Value::Array(files));
}

#[cfg(unix)]
#[test]
fn a_runtime_replaced_since_it_was_captured_is_refused() {
    let bound = Bound::new(0o700);
    let answer = bound.bind(json!([]), bound.mtime_ns() + 1);
    assert_eq!(
        answer["error"]["transition"],
        "native_runtime_generation_changed"
    );
}

#[cfg(unix)]
#[test]
fn a_runtime_another_user_could_write_is_refused() {
    let bound = Bound::new(0o777);
    let answer = bound.bind(json!([]), bound.mtime_ns());
    let reason = answer["error"]["integrity"].as_str().unwrap_or_default();
    assert!(reason.starts_with("codex_hook_artifact_"), "{answer}");
}

#[test]
fn a_predecessor_manifest_is_authenticated_by_the_runtime_or_refused() {
    let answer = ask(
        "publication_inverse_pinned",
        json!({"manifest_text": "not json", "dependencies": []}),
    );
    assert_eq!(answer["error"]["integrity"], "codex_hook_manifest_invalid");
    let answer = ask("publication_inverse_pinned", json!({"dependencies": []}));
    assert_eq!(answer["error"]["transition"], "files_invalid");
}

#[test]
fn a_verification_without_a_captured_plan_is_refused() {
    let answer = ask("publication_inverse_verify", json!({}));
    assert_eq!(
        answer["error"]["transition"],
        "publication_inverse_plan_invalid"
    );
}

#[test]
fn an_expired_hook_deadline_stops_a_verification_first() {
    let answer = ask(
        "publication_inverse_verify",
        json!({"budget": {"hook_ms": 0}}),
    );
    assert_eq!(
        answer["error"]["integrity"],
        "codex_hook_validation_deadline_expired"
    );
}
