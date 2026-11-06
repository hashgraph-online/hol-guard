#![cfg(target_os = "macos")]

//! The workspace sandbox keeps the caller's sealed tool directories on PATH,
//! so `pnpm` and the caller's `node` still resolve inside it, and never
//! Guard's package shims or a credential folder. A directory of the
//! workspace's own keeps its place on PATH, so the project's own tools
//! resolve to the same files inside the sandbox, and a venv's launchers also
//! bring the interpreter install they link out to.

use guard_command::restricted_pytest::evaluate;
use serde_json::json;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    let nonce = crate::unique_nanos::unique_nanos();
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

/// Whether `entry` is a developer directory's `usr/bin`.
fn developer_tools_entry(entry: &str) -> bool {
    entry != "/usr/bin"
        && entry.ends_with("/usr/bin")
        && (entry.starts_with("/Applications/") || entry.starts_with("/Library/Developer/"))
}

/// `sandbox_path` without the developer tools directory a plan puts just
/// ahead of `/usr/bin` on a host that selects one.
fn without_developer_tools(sandbox_path: &serde_json::Value) -> serde_json::Value {
    let entries: Vec<&str> = sandbox_path.as_str().unwrap().split(':').collect();
    let kept: Vec<&str> = entries
        .iter()
        .enumerate()
        .filter(|(at, entry)| {
            !(developer_tools_entry(entry) && entries.get(at + 1) == Some(&"/usr/bin"))
        })
        .map(|(_, entry)| *entry)
        .collect();
    json!(kept.join(":"))
}

/// The developer directory macOS's `/usr/bin` shims forward into: the one
/// `xcode-select` recorded, or the default they fall back to.
fn selected_developer_dir() -> Option<PathBuf> {
    [
        "/private/var/select/developer_dir",
        "/private/var/db/xcode_select_link",
    ]
    .iter()
    .find_map(|link| std::fs::read_link(link).ok())
    .or_else(|| {
        [
            "/Applications/Xcode.app/Contents/Developer",
            "/Library/Developer/CommandLineTools",
        ]
        .iter()
        .map(PathBuf::from)
        .find(|candidate| candidate.is_dir())
    })?
    .canonicalize()
    .ok()
}

/// Whether `developer` lies where Guard accepts a developer directory: under
/// `/Library/Developer`, or inside an app bundle directly in `/Applications`.
fn sealed_developer_prefix(developer: &Path) -> bool {
    if developer.starts_with("/Library/Developer") {
        return true;
    }
    developer
        .strip_prefix("/Applications")
        .ok()
        .and_then(|rest| rest.components().next())
        .is_some_and(|bundle| Path::new(bundle.as_os_str()).extension() == Some("app".as_ref()))
}

/// The file the shell finds for the bare `program` on `search_path`.
fn find(program: &str, search_path: &str) -> Option<PathBuf> {
    search_path
        .split(':')
        .map(|entry| Path::new(entry).join(program))
        .find(|candidate| {
            candidate.metadata().is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
}

#[test]
fn a_bare_shim_name_finds_the_developer_tool_inside_the_sandbox() {
    // `/usr/bin/python3` is a shim. Run inside the sandbox, its lookup spawns
    // `xcodebuild`, whose diagnostics land in the command's own output, so
    // the sandbox PATH must find the interpreter the shim forwards to first.
    // Guard executes only from a root-owned developer directory under
    // `/Library/Developer` or an app in `/Applications`.
    let Some(forwarded) = selected_developer_dir()
        .filter(|developer| sealed_developer_prefix(developer))
        .filter(|developer| {
            developer
                .metadata()
                .is_ok_and(|metadata| metadata.uid() == 0)
        })
        .and_then(|developer| developer.join("usr/bin/python3").canonicalize().ok())
    else {
        eprintln!("skipping developer shim test: no root-owned developer python3");
        return;
    };
    let root = root();
    let home = dir(&root, "home", 0o755);
    let workspace = dir(&root, "repo", 0o755);
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    let reply = evaluate(
        "prepare_workspace_contained",
        &json!({
            "text": "ls",
            "workspace": workspace,
            "cwd": workspace,
            "platform": "darwin",
            "search_path": "/usr/bin:/bin",
            "home": home,
        }),
    );
    let sandbox_path = reply["value"]["sandbox_path"].as_str().unwrap();
    let found = find("python3", sandbox_path).and_then(|found| found.canonicalize().ok());
    assert_eq!(found.as_deref(), Some(forwarded.as_path()), "{reply}");
    assert!(sandbox_path.ends_with(":/usr/bin:/bin"), "{reply}");
    let _ = std::fs::remove_dir_all(&root);
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
    let inside = dir(&root, "repo/node_modules/.bin", 0o755);
    let open = dir(&root, "repo/open", 0o777);
    let mut search_path: Vec<String> = refused.iter().map(|path| text(path.as_path())).collect();
    search_path.extend([text(&open), text(&inside), text(&tools), text(&pnpm)]);
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
    // The workspace's own tool directory keeps its place; one anyone else
    // could write does not.
    assert_eq!(
        without_developer_tools(&plan["sandbox_path"]),
        json!(format!(
            "{}:{}:{}:/usr/bin:/bin",
            text(&inside),
            text(&tools),
            text(&pnpm)
        )),
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
    // Being on the sandbox PATH is not a grant: the workspace is read and run
    // already, and nothing else of the caller's is added for it.
    for path in refused.iter().chain([&inside, &open, &home]) {
        assert!(!roots.contains(&text(path).as_str()), "{}", path.display());
    }
    let _ = std::fs::remove_dir_all(root);
}

/// `<workspace>/.venv`, whose `bin/python` links to `base` and whose
/// `pyvenv.cfg` names `home`.
fn venv(workspace: &Path, base: &Path, home: &Path) -> PathBuf {
    let venv = workspace.join(".venv");
    std::fs::create_dir_all(venv.join("bin")).unwrap();
    std::fs::create_dir_all(venv.join("lib/python3/site-packages")).unwrap();
    std::fs::write(
        venv.join("pyvenv.cfg"),
        format!(
            "home = {}\ninclude-system-site-packages = false\n",
            home.display()
        ),
    )
    .unwrap();
    std::os::unix::fs::symlink(base, venv.join("bin/python")).unwrap();
    std::os::unix::fs::symlink("python", venv.join("bin/python3")).unwrap();
    venv
}

#[test]
fn a_workspace_venv_keeps_its_bin_and_grants_its_interpreter_install() {
    let Some(bin) = ["/usr/local/bin", "/opt/homebrew/bin"]
        .iter()
        .find_map(|bin| Path::new(bin).canonicalize().ok())
    else {
        eprintln!("skipping workspace venv test: no trusted prefix");
        return;
    };
    let prefix = bin.parent().unwrap().to_path_buf();
    let root = root();
    let home = dir(&root, "home", 0o755);
    let workspace = dir(&root, "repo", 0o755);
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::write(workspace.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
    let venv = venv(&workspace, Path::new("/usr/bin/python3"), &bin);
    let search_path = [
        text(&venv.join("bin")),
        text(&workspace.join("node_modules/.bin")),
        "/usr/bin".into(),
        "/bin".into(),
    ];
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
        without_developer_tools(&plan["sandbox_path"]),
        json!(format!("{}:/usr/bin:/bin", text(&venv.join("bin")))),
        "{reply}"
    );
    let roots: Vec<&str> = plan["exec_roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|root| root.as_str().unwrap())
        .collect();
    // The interpreter's own directory is granted, never the trusted root that
    // holds every other program installed below it.
    assert!(roots.contains(&text(&bin).as_str()), "{roots:?}");
    assert!(!roots.contains(&text(&prefix).as_str()), "{roots:?}");
    assert!(!roots.contains(&text(&venv).as_str()), "{roots:?}");
    let _ = std::fs::remove_dir_all(&root);
}
