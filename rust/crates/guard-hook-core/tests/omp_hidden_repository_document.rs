//! An Oh My Pi `read` of a plugin manifest the session's repository keeps
//! below a hidden directory, such as `.claude-plugin/plugin.json`, from the
//! checkout or from a linked worktree `git worktree add` left in `/tmp`.
//! PreToolUse admits the read; the output review repeats that proof and
//! still scans the file, instead of withholding the result as unreviewable.
#![cfg(unix)]

use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MANIFEST: &str = ".claude-plugin/plugin.json";
const MANIFEST_TEXT: &str = "{\n  \"name\": \"app\",\n  \"version\": \"1.2.0\"\n}\n";

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Layout {
    home: PathBuf,
    main: PathBuf,
    linked: PathBuf,
    sibling: PathBuf,
    temp: PathBuf,
    base: PathBuf,
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.temp);
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// A checkout below home with a linked worktree in `/tmp`, registered the way
/// Git registers one, and an unrelated sibling checkout.
fn layout() -> Layout {
    let nonce = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let label = format!("guard-omp-hidden-doc-{}-{nonce}", std::process::id());
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(&label);
    std::fs::create_dir_all(base.join("home/app/.git/worktrees/app-fix")).unwrap();
    std::fs::create_dir_all(base.join("home/other/.git")).unwrap();
    let base = std::fs::canonicalize(base).unwrap();
    let home = base.join("home");
    let main = home.join("app");
    let sibling = home.join("other");
    let temp = std::fs::canonicalize("/tmp").unwrap().join(&label);
    let linked = temp.join("app-fix");
    std::fs::create_dir_all(&linked).unwrap();
    let admin = main.join(".git/worktrees/app-fix");
    std::fs::write(
        linked.join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    std::fs::write(
        admin.join("gitdir"),
        format!("{}\n", linked.join(".git").display()),
    )
    .unwrap();
    Layout {
        home,
        main,
        linked,
        sibling,
        temp,
        base,
    }
}

fn plant(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn read_result(layout: &Layout, cwd: &Path, path: &Path, file_text: &str) -> NativeHookRequestV1 {
    // OMP's read tool drops the file's final newline.
    let output = file_text.strip_suffix('\n').unwrap_or(file_text);
    let target = path.to_string_lossy().into_owned();
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("omp-hidden-repository-document".into()),
        harness: "omp".into(),
        event_name: "PostToolUse".into(),
        payload: json!({
            "tool_name": "read", "tool_input": {"path": target},
            "tool_response": output,
            "guard_source_ref": {"version": 1, "kind": "source_file",
                "path": target, "tool_input_path": target,
                "output_sha256": format!("{:x}", Sha256::digest(output.as_bytes())),
                "output_chars": output.chars().count()}
        }),
        cwd: Some(cwd.to_string_lossy().into()),
        home_dir: layout.home.to_string_lossy().into(),
        guard_home: layout.base.join("guard").to_string_lossy().into(),
        source_ref_external_allowed: true,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

fn token() -> String {
    format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30))
}

#[test]
fn a_plugin_manifest_in_the_checkout_or_its_tmp_worktree_keeps_its_output() {
    let layout = layout();
    let in_main = layout.main.join(MANIFEST);
    let in_linked = layout.linked.join(MANIFEST);
    plant(&in_main, MANIFEST_TEXT);
    plant(&in_linked, MANIFEST_TEXT);
    for (cwd, path) in [
        (&layout.main, &in_main),
        (&layout.main, &in_linked),
        (&layout.linked, &in_linked),
    ] {
        let result = review_post_tool(&read_result(&layout, cwd, path, MANIFEST_TEXT));
        assert_eq!(
            result.model_output_action,
            "allow_original",
            "{} from {}: {result:?}",
            path.display(),
            cwd.display()
        );
        assert_eq!(result.reason_code, "source_full_scan_allow", "{result:?}");
    }
}

#[test]
fn a_plugin_manifest_holding_a_secret_is_still_withheld() {
    let layout = layout();
    let body = format!(
        "{{\n  \"name\": \"app\",\n  \"token\": \"{}\"\n}}\n",
        token()
    );
    let path = layout.linked.join(MANIFEST);
    plant(&path, &body);
    // The model is shown clean text, but the file on disk holds a secret.
    let shown = read_result(&layout, &layout.main, &path, MANIFEST_TEXT);
    assert_eq!(review_post_tool(&shown).reason_code, "source_secret_match");
    let leaked = read_result(&layout, &layout.main, &path, &body);
    assert_eq!(review_post_tool(&leaked).reason_code, "source_secret_match");
}

#[test]
fn other_hidden_files_and_other_repositories_stay_unreviewable() {
    let layout = layout();
    let refused = [
        layout.linked.join(".private/notes.md"),
        layout.linked.join(".claude-plugin/.mcp.json"),
        layout.linked.join(".vscode/tasks.json"),
        layout.sibling.join(MANIFEST),
    ];
    for path in &refused {
        plant(path, MANIFEST_TEXT);
        let result = review_post_tool(&read_result(&layout, &layout.main, path, MANIFEST_TEXT));
        assert_ne!(
            result.model_output_action,
            "allow_original",
            "{}: {result:?}",
            path.display()
        );
    }
}
