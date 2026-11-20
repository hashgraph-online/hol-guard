use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::*;

fn home() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("temp dir");
    let base = fs::canonicalize(dir.path()).expect("canonical temp dir");
    (dir, base)
}

fn write(path: &Path, body: &[u8]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("parent directory");
    fs::write(path, body).expect("write");
}

fn digest(body: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(body)))
}

fn text(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

fn admit_one(artifact_type: &str, path: &Path, workspace: Option<&Path>) -> Value {
    let answer = dispatch(&json!({
        "op": "admit",
        "workspace_dir": workspace.map(text),
        "candidates": [{"artifact_type": artifact_type, "path": text(path)}],
    }))
    .expect("admit answer");
    answer["allowed_roots"][0].clone()
}

fn read_one(path: &Path, root: &Path, content_hash: &str) -> Value {
    dispatch(&json!({
        "op": "read",
        "path": text(path),
        "allowed_root": text(root),
        "content_hash": content_hash,
    }))
    .expect("read answer")
}

#[test]
fn a_nested_skill_document_is_admitted_under_its_nearest_skills_root() {
    let (_dir, base) = home();
    let skills = base.join(".codex/Skills");
    let nested = skills.join("ops/review/SKILL.md");
    write(&nested, b"# review\n");
    assert_eq!(admit_one("skill", &nested, None), json!(text(&skills)));

    let shallow = skills.join("SKILL.md");
    write(&shallow, b"# top\n");
    assert_eq!(admit_one("skill", &shallow, None), Value::Null);

    let supplementary = skills.join("ops/review/notes.md");
    write(&supplementary, b"notes\n");
    assert_eq!(admit_one("skill", &supplementary, None), Value::Null);

    let outside = base.join("tools/review/SKILL.md");
    write(&outside, b"# outside\n");
    assert_eq!(admit_one("skill", &outside, None), Value::Null);

    let missing = skills.join("ops/missing/SKILL.md");
    assert_eq!(admit_one("skill", &missing, None), Value::Null);
}

#[test]
fn a_markdown_instruction_is_admitted_only_under_the_workspace() {
    let (_dir, base) = home();
    let workspace = base.join("workspace");
    let agents = workspace.join("AGENTS.MD");
    write(&agents, b"# rules\n");
    assert_eq!(
        admit_one("instruction", &agents, Some(&workspace)),
        json!(text(&workspace))
    );
    assert_eq!(admit_one("instruction", &agents, None), Value::Null);

    let plain = workspace.join("rules.txt");
    write(&plain, b"rules\n");
    assert_eq!(
        admit_one("instruction", &plain, Some(&workspace)),
        Value::Null
    );

    let dotfile = workspace.join(".md");
    write(&dotfile, b"rules\n");
    assert_eq!(
        admit_one("instruction", &dotfile, Some(&workspace)),
        Value::Null
    );

    let elsewhere = base.join("other/AGENTS.md");
    write(&elsewhere, b"# other\n");
    assert_eq!(
        admit_one("instruction", &elsewhere, Some(&workspace)),
        Value::Null
    );
}

#[test]
fn a_relative_path_is_never_admitted() {
    let answer = dispatch(&json!({
        "op": "admit",
        "workspace_dir": "workspace",
        "candidates": [
            {"artifact_type": "skill", "path": "skills/ops/review/SKILL.md"},
            {"artifact_type": "instruction", "path": "workspace/AGENTS.md"},
        ],
    }))
    .expect("admit answer");
    assert_eq!(answer, json!({"allowed_roots": [null, null]}));
}

#[test]
fn the_read_returns_the_exact_body_only_while_it_matches_the_advertised_digest() {
    let (_dir, base) = home();
    let skills = base.join("skills");
    let path = skills.join("ops/review/SKILL.md");
    write(&path, b"# review\n");
    let answer = read_one(&path, &skills, &digest(b"# review\n"));
    assert_eq!(answer["size"], 9);
    assert_eq!(
        STANDARD
            .decode(answer["body_base64"].as_str().expect("body"))
            .expect("base64"),
        b"# review\n"
    );

    write(&path, b"# changed\n");
    let answer = read_one(&path, &skills, &digest(b"# review\n"));
    assert_eq!(answer, json!({"body_base64": null}));

    let outside = base.join("elsewhere/SKILL.md");
    write(&outside, b"# review\n");
    let answer = read_one(&outside, &skills, &digest(b"# review\n"));
    assert_eq!(answer, json!({"body_base64": null}));
}

#[test]
fn an_empty_body_is_read_and_an_oversized_one_is_not() {
    let (_dir, base) = home();
    let skills = base.join("skills");
    let empty = skills.join("ops/empty/SKILL.md");
    write(&empty, b"");
    let answer = read_one(&empty, &skills, &digest(b""));
    assert_eq!(answer, json!({"body_base64": "", "size": 0}));

    let large = vec![b'a'; 1024 * 1024 + 1];
    let oversized = skills.join("ops/large/SKILL.md");
    write(&oversized, &large);
    let answer = read_one(&oversized, &skills, &digest(&large));
    assert_eq!(answer, json!({"body_base64": null}));
}

#[cfg(unix)]
mod links {
    use super::*;

    fn link(target: &Path, at: &Path) {
        fs::create_dir_all(at.parent().expect("parent")).expect("parent directory");
        std::os::unix::fs::symlink(target, at).expect("symlink");
    }

    #[test]
    fn a_linked_primary_document_is_refused() {
        let (_dir, base) = home();
        let skills = base.join("skills");
        let real = skills.join("ops/real/SKILL.md");
        write(&real, b"# real\n");
        let linked = skills.join("ops/linked/SKILL.md");
        link(&real, &linked);
        assert_eq!(admit_one("skill", &linked, None), Value::Null);
        let answer = read_one(&linked, &skills, &digest(b"# real\n"));
        assert_eq!(answer, json!({"body_base64": null}));
    }

    #[test]
    fn a_linked_skills_root_or_skill_directory_is_refused() {
        let (_dir, base) = home();
        let real_root = base.join("real-skills");
        write(&real_root.join("ops/review/SKILL.md"), b"# review\n");
        let linked_root = base.join("agent/skills");
        link(&real_root, &linked_root);
        let through_root = linked_root.join("ops/review/SKILL.md");
        assert_eq!(admit_one("skill", &through_root, None), Value::Null);

        let skills = base.join("skills");
        write(&base.join("real-dir/SKILL.md"), b"# dir\n");
        link(&base.join("real-dir"), &skills.join("ops/dir"));
        assert_eq!(
            admit_one("skill", &skills.join("ops/dir/SKILL.md"), None),
            Value::Null
        );
    }
}

/// A directory link, or `None` where this account may not create one.
fn link_dir(target: &Path, at: &Path) -> Option<()> {
    fs::create_dir_all(at.parent()?).ok()?;
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, at);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(target, at);
    made.ok()
}

#[test]
fn a_link_above_the_skills_root_is_followed() {
    let (_dir, base) = home();
    let real_workspace = base.join("workspace-real");
    write(
        &real_workspace.join(".gemini/skills/review/SKILL.md"),
        b"# review\n",
    );
    let workspace = base.join("workspace-link");
    if link_dir(&real_workspace, &workspace).is_none() {
        // Linking needs a privilege a Windows account may not hold.
        assert!(cfg!(windows), "unix accounts can always link");
        return;
    }
    let skills = workspace.join(".gemini/skills");
    let path = skills.join("review/SKILL.md");
    assert_eq!(admit_one("skill", &path, None), json!(text(&skills)));
    let answer = read_one(&path, &skills, &digest(b"# review\n"));
    assert_eq!(answer["size"], 9);
}

#[test]
fn malformed_requests_are_invalid() {
    for args in [
        json!([]),
        json!({"op": "unknown"}),
        json!({"op": "admit", "candidates": {}}),
        json!({"op": "admit", "workspace_dir": 1, "candidates": []}),
        json!({"op": "admit", "candidates": [[]]}),
        json!({"op": "admit", "candidates": [{"artifact_type": "plugin", "path": "/x"}]}),
        json!({"op": "admit", "candidates": [{"artifact_type": "skill"}]}),
        json!({"op": "read", "path": 1, "allowed_root": "/x", "content_hash": "sha256:00"}),
        json!({"op": "read", "path": "/x", "allowed_root": "/x"}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
