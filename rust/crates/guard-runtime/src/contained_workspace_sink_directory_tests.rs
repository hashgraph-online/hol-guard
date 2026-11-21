use super::*;
use serde_json::json;

struct Fixture {
    _home: tempfile::TempDir,
    _root: tempfile::TempDir,
    home: PathBuf,
    workspace: PathBuf,
}

fn fixture() -> Fixture {
    let home = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let root = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::create_dir(root.path().join("my dir")).unwrap();
    std::fs::write(root.path().join("file"), "").unwrap();
    std::fs::create_dir(home.path().join("x")).unwrap();
    Fixture {
        home: std::fs::canonicalize(home.path()).unwrap(),
        workspace: std::fs::canonicalize(root.path()).unwrap(),
        _home: home,
        _root: root,
    }
}

fn input(value: Value) -> Map<String, Value> {
    let Value::Object(input) = value else {
        unreachable!()
    };
    input
}

#[test]
fn the_session_directory_is_kept_for_an_empty_or_root_value() {
    let fixture = fixture();
    let (workspace, home) = (&fixture.workspace, &fixture.home);
    for value in ["", "/", "//", workspace.to_str().unwrap()] {
        assert_eq!(
            requested(&json!(value), workspace, home),
            Some(None),
            "{value}"
        );
    }
}

#[test]
fn a_value_resolves_from_the_session_directory_or_home() {
    let fixture = fixture();
    let (workspace, home) = (&fixture.workspace, &fixture.home);
    assert_eq!(
        requested(&json!("sub"), workspace, home),
        Some(Some(workspace.join("sub")))
    );
    assert_eq!(requested(&json!("sub/.."), workspace, home), Some(None));
    assert_eq!(
        requested(&json!("~"), workspace, home),
        Some(Some(home.clone()))
    );
    assert_eq!(
        requested(&json!("~/x"), workspace, home),
        Some(Some(home.join("x")))
    );
}

#[test]
fn a_form_the_host_rewrites_is_refused() {
    let fixture = fixture();
    let (workspace, home) = (&fixture.workspace, &fixture.home);
    for value in [
        "~root",
        "@sub",
        ":sub",
        "file:sub",
        "https://example.test/sub",
        "sub\\x",
        "sub\u{e9}",
        "sub\n",
        "missing",
        "file",
    ] {
        assert_eq!(requested(&json!(value), workspace, home), None, "{value:?}");
    }
    assert_eq!(requested(&json!(1), workspace, home), None);
}

#[test]
fn the_argument_becomes_a_leading_directory_change() {
    let fixture = fixture();
    let (workspace, home) = (&fixture.workspace, &fixture.home);
    let changed = directory_change(
        &input(json!({ "command": "pytest -q", "cwd": "sub", "timeout": 5 })),
        workspace,
        home,
    )
    .unwrap();
    assert_eq!(
        Value::Object(changed),
        json!({
            "command": format!("cd {} && pytest -q", workspace.join("sub").display()),
            "timeout": 5,
        })
    );
    let quoted = directory_change(
        &input(json!({ "command": "pytest -q", "cwd": "my dir" })),
        workspace,
        home,
    )
    .unwrap();
    assert_eq!(
        quoted["command"],
        format!("cd '{}' && pytest -q", workspace.join("my dir").display())
    );
    // The session directory itself drops the argument and keeps the text.
    let root = directory_change(
        &input(json!({ "command": "pytest -q", "cwd": "/" })),
        workspace,
        home,
    )
    .unwrap();
    assert_eq!(Value::Object(root), json!({ "command": "pytest -q" }));
    assert_eq!(
        directory_change(
            &input(json!({ "command": "pytest -q", "cwd": "@x" })),
            workspace,
            home
        ),
        None
    );
}

#[test]
fn the_sandbox_roots_only_at_the_workspace_or_a_sibling_root() {
    let fixture = fixture();
    let (workspace, home) = (&fixture.workspace, &fixture.home);
    assert!(rootable(workspace, workspace, home));
    assert!(!rootable(&home.join("x"), workspace, home));
    // A folder below the workspace runs through the `cd` form, which keeps
    // the workspace root and so its protected folders.
    // A nested repository is below the workspace too.
    std::fs::create_dir_all(workspace.join("vendor/lib/.git")).unwrap();
    for folder in [
        "sub",
        ".git",
        ".git/hooks",
        ".claude",
        ".vscode",
        "vendor/lib",
    ] {
        std::fs::create_dir_all(workspace.join(folder)).unwrap();
        assert!(
            !rootable(&workspace.join(folder), workspace, home),
            "{folder}"
        );
    }
}
