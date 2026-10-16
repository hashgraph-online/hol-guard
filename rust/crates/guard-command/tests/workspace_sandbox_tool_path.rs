#![cfg(target_os = "macos")]

//! The workspace sandbox keeps the caller's sealed tool directories on PATH,
//! so `pnpm` and the caller's `node` still resolve inside it, and never a
//! directory in the workspace, Guard's package shims or a credential folder.

use guard_command::restricted_pytest::evaluate;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "guard-sandbox-tools-{}-{nonce}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    root.canonicalize().unwrap()
}

/// `relative` below `root`, each new directory created with `mode`.
fn dir(root: &Path, relative: &str, mode: u32) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        path.push(component);
        if !path.exists() {
            std::fs::create_dir(&path).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }
    path
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn sealed_user_tool_directories_stay_on_the_sandbox_path() {
    let root = root();
    let home = dir(&root, "home", 0o755);
    let tools = dir(&root, "home/.local/bin", 0o755);
    let pnpm = dir(&root, "home/Library/pnpm", 0o755);
    let refused = [
        dir(&root, "home/.hol-guard/package-shims/bin", 0o755),
        dir(&root, "home/Library/Keychains/bin", 0o755),
        dir(&root, "home/.ssh/bin", 0o755),
        dir(&root, "home/tools", 0o755),
        dir(&root, "open/bin", 0o777),
    ];
    let workspace = dir(&root, "repo", 0o755);
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    let inside = dir(&root, "repo/bin", 0o755);
    let mut search_path: Vec<String> = refused.iter().map(|path| text(path.as_path())).collect();
    search_path.extend([text(&inside), text(&tools), text(&pnpm)]);
    search_path.extend(["/usr/bin".into(), "/bin".into()]);
    let reply = evaluate(
        "prepare_workspace_contained",
        &json!({
            "text": "ls",
            "workspace": workspace,
            "cwd": workspace,
            "platform": "darwin",
            "search_path": search_path.join(":"),
            "home": home,
        }),
    );
    let plan = &reply["value"];
    assert_eq!(
        plan["sandbox_path"],
        json!(format!("{}:{}:/usr/bin:/bin", text(&tools), text(&pnpm))),
        "{reply}"
    );
    let roots: Vec<&str> = plan["exec_roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|root| root.as_str().unwrap())
        .collect();
    assert!(roots.contains(&text(&tools).as_str()), "{roots:?}");
    assert!(roots.contains(&text(&pnpm).as_str()), "{roots:?}");
    for path in refused.iter().chain([&inside, &home]) {
        assert!(!roots.contains(&text(path).as_str()), "{}", path.display());
    }
    let _ = std::fs::remove_dir_all(root);
}
