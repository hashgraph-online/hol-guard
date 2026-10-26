#![cfg(unix)]
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};

static FIXTURES: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: std::path::PathBuf,
    home: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A session folder beside a notes folder, a linked cwd that points
/// elsewhere, and a protected folder one level up.
fn fixture() -> Fixture {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pretool-parent-relative-writes")
        .join(format!(
            "home-{}-{}-{}",
            std::process::id(),
            FIXTURES.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let home = root.join("home");
    for file in [
        "work/session/README.md",
        "work/notes/existing.md",
        "elsewhere/session/README.md",
        "elsewhere/notes/existing.md",
        ".ssh/config",
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "synthetic fixture\n").unwrap();
    }
    std::os::unix::fs::symlink(home.join("elsewhere/session"), home.join("work/linked")).unwrap();
    Fixture { root, home }
}

fn host_write(
    f: &Fixture,
    harness: &str,
    cwd: &str,
    path: &str,
) -> guard_contracts::PreToolResultV1 {
    let (tool, input): (&str, Value) = match harness {
        "omp" => ("write", json!({"path": path, "content": "x\n"})),
        _ => ("Write", json!({"file_path": path, "content": "x\n"})),
    };
    evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name": tool, "tool_input": input}),
        None,
        None,
        f.home.to_str(),
        f.home.join(cwd).to_str(),
    )
}

#[test]
fn a_sibling_folder_named_through_parent_is_an_ordinary_write() {
    let f = fixture();
    for harness in ["omp", "zcode", "claude-code"] {
        for path in [
            "../notes/new.md",
            "../notes/existing.md",
            "./../notes/deeper/new.md",
            "../session/../notes/new.md",
        ] {
            let result = host_write(&f, harness, "work/session", path);
            assert_eq!(
                (result.minimum_action.as_str(), result.reason_code.as_str()),
                ("allow", "native_exact_safe_file_write"),
                "{harness} {path}"
            );
        }
    }
}

#[test]
fn parent_paths_keep_every_location_screen() {
    let f = fixture();
    for harness in ["omp", "zcode", "claude-code"] {
        for path in [
            "../../.ssh/config",
            "../../.ssh/new_key",
            "../../../../../../../../../../../../etc/new.conf",
            "../session/.git/hooks/pre-commit",
        ] {
            let result = host_write(&f, harness, "work/session", path);
            assert_ne!(result.minimum_action, "allow", "{harness} {path}");
        }
    }
}

#[test]
fn a_linked_cwd_where_spelling_and_filesystem_disagree_is_refused() {
    let f = fixture();
    // The host resolves `work/linked/../notes` to `work/notes`; the
    // filesystem walks to `elsewhere/notes`. Neither may be assumed.
    for harness in ["omp", "zcode", "claude-code"] {
        let result = host_write(&f, harness, "work/linked", "../notes/existing.md");
        assert_ne!(result.minimum_action, "allow", "{harness}: {result:?}");
    }
}

#[test]
fn shell_writes_still_refuse_parent_paths() {
    let f = fixture();
    let result = evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name": "bash", "tool_input": {"command": "touch ../notes/new.md"}}),
        None,
        None,
        f.home.to_str(),
        f.home.join("work/session").to_str(),
    );
    assert_ne!(
        result.reason_code, "native_exact_safe_file_write",
        "{result:?}"
    );
}
