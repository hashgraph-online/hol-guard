use super::*;

fn root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-wl-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for directory in ["ws", "private", "overlay/upper", "overlay/work"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    root.canonicalize().unwrap()
}

fn input(root: &Path, command: &[&str]) -> Input {
    Input {
        // Any root-owned system executable stands in for bubblewrap here.
        backend_executable: PathBuf::from("/bin/sh"),
        workspace: root.join("ws"),
        private_root: root.join("private"),
        upper: root.join("overlay/upper"),
        work: root.join("overlay/work"),
        exec_roots: vec![root.join("ws/.venv"), PathBuf::from("/opt/tool")],
        read_files: Vec::new(),
        command: command.iter().map(|value| (*value).to_owned()).collect(),
        linked_git: None,
        shared_upper: None,
        shared_work: None,
        _search_path: String::new(),
    }
}

fn after(argv: &[String], flag: &str, value: &str) -> bool {
    argv.windows(2)
        .any(|pair| pair[0] == flag && pair[1] == value)
}

#[test]
fn the_workspace_is_an_overlay_with_credentials_hidden() {
    let root = root("argv");
    let ws = root.join("ws");
    std::fs::write(ws.join(".env"), "SECRET=1").unwrap();
    std::fs::create_dir_all(ws.join("app/.ssh")).unwrap();
    std::fs::write(ws.join("app/.ssh/id_rsa"), "key").unwrap();
    std::fs::write(ws.join("app/main.py"), "").unwrap();
    let argv = workspace_argv(&input(&root, &["/bin/sh", "-c", "make"])).unwrap();
    let ws_text = ws.to_string_lossy().into_owned();
    for flag in ["--unshare-all", "--die-with-parent", "--new-session"] {
        assert!(argv.iter().any(|value| value == flag), "{flag}");
    }
    assert!(after(&argv, "--overlay-src", &ws_text));
    assert!(after(&argv, "--ro-bind", "/dev/null"));
    assert!(after(&argv, "/dev/null", &format!("{ws_text}/.env")));
    assert!(after(&argv, "--tmpfs", &format!("{ws_text}/app/.ssh")));
    assert!(after(&argv, "--remount-ro", &format!("{ws_text}/app/.ssh")));
    assert!(!argv.iter().any(|value| value.ends_with("id_rsa")));
    // An exec root inside the workspace would shadow the overlay.
    assert!(!argv.iter().any(|value| value.ends_with("/ws/.venv")));
    assert!(after(&argv, "--ro-bind-try", "/opt/tool"));
    assert_eq!(&argv[argv.len() - 4..], ["--", "/bin/sh", "-c", "make"]);
    let overlay = argv.iter().position(|value| value == "--overlay").unwrap();
    let mask = argv.iter().position(|value| value == "/dev/null").unwrap();
    assert!(overlay < mask, "masks mount over the overlay");
}

#[test]
fn a_credential_inside_a_granted_package_tree_is_hidden_too() {
    // A dependency tree is granted whole, so the rest of it comes with the
    // tool directory that earned the grant. What it holds is withheld the
    // way the workspace's own credentials are.
    let root = root("package-tree");
    let tree = root.join("node_modules");
    let package = tree.join("harness-cli");
    std::fs::create_dir_all(package.join(".ssh")).unwrap();
    std::fs::write(package.join(".npmrc"), "//registry/:_authToken=x").unwrap();
    std::fs::write(tree.join(".env"), "TOKEN=1").unwrap();
    std::fs::write(package.join("index.js"), "").unwrap();
    let mut request = input(&root, &["/bin/sh", "-c", "true"]);
    request.exec_roots = vec![tree.clone(), PathBuf::from("/opt/tool")];
    let argv = workspace_argv(&request).unwrap();
    let text = |path: PathBuf| path.to_string_lossy().into_owned();
    assert!(after(&argv, "--ro-bind-try", &text(tree.clone())));
    assert!(after(&argv, "/dev/null", &text(package.join(".npmrc"))));
    assert!(after(&argv, "/dev/null", &text(tree.join(".env"))));
    assert!(after(&argv, "--tmpfs", &text(package.join(".ssh"))));
    assert!(!argv.iter().any(|value| value.ends_with("index.js")));
    // The grant is still read-only, and the masks mount over it.
    let bound = argv
        .windows(2)
        .position(|pair| pair[0] == "--ro-bind-try" && pair[1] == text(tree.clone()))
        .unwrap();
    let masked = argv
        .windows(2)
        .position(|pair| pair[1] == text(package.join(".npmrc")))
        .unwrap();
    assert!(bound < masked, "{argv:?}");
    // A narrow tool directory grant names no tree and is not walked.
    let tools = root.join("tools/bin");
    std::fs::create_dir_all(&tools).unwrap();
    std::fs::write(tools.join(".npmrc"), "x").unwrap();
    request.exec_roots = vec![tools.clone()];
    let argv = workspace_argv(&request).unwrap();
    assert!(!argv.iter().any(|value| value.ends_with("tools/bin/.npmrc")));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_directory_of_a_granted_tree_that_cannot_be_listed_is_hidden_not_refused() {
    // An installed package may hold a directory this account cannot list.
    // Refusing the launch over it would hand back the review the grant
    // removes, so the directory is hidden whole and the run goes ahead.
    if nix::unistd::geteuid().is_root() {
        // Root lists a directory whatever its mode says.
        return;
    }
    let root = root("tree-unreadable");
    let tree = root.join("node_modules");
    let closed = tree.join("harness-cli/fixtures");
    std::fs::create_dir_all(&closed).unwrap();
    std::fs::write(closed.join("signing.key"), "x").unwrap();
    std::fs::write(tree.join(".npmrc"), "//registry/:_authToken=x").unwrap();
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let mut request = input(&root, &["/bin/sh", "-c", "true"]);
    request.exec_roots = vec![tree.clone()];
    let argv = workspace_argv(&request).unwrap();
    let text = |path: PathBuf| path.to_string_lossy().into_owned();
    assert!(after(&argv, "--tmpfs", &text(closed.clone())));
    // What the walk could read is still named file by file.
    assert!(after(&argv, "/dev/null", &text(tree.join(".npmrc"))));
    // Nothing is mounted under the hidden directory, which would fail bwrap.
    assert!(!argv.iter().any(|value| value.ends_with("signing.key")));
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn hidden_directories_count_against_the_mask_budget_too() {
    // Hiding a directory mounts over it, so a tree full of directories that
    // cannot be listed reaches the same cap a tree full of credentials does.
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let root = root("tree-hidden-budget");
    let tree = root.join("node_modules/harness-cli");
    std::fs::create_dir_all(&tree).unwrap();
    let closed: Vec<PathBuf> = (0..=MAX_MASKS)
        .map(|n| tree.join(format!("f{n}")))
        .collect();
    for directory in &closed {
        std::fs::create_dir(directory).unwrap();
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let mut request = input(&root, &["/bin/sh", "-c", "true"]);
    request.exec_roots = vec![root.join("node_modules")];
    let error = workspace_argv(&request).unwrap_err();
    assert_eq!(error.reason_code, PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE);
    assert!(error.message.contains("package tree"), "{}", error.message);
    for directory in &closed {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_tree_holding_more_credentials_than_the_budget_refuses_the_launch() {
    // The masks are mount arguments, so their number is capped. A tree past
    // the cap is refused with a reason of its own rather than bound with the
    // credentials it holds left readable.
    let root = root("tree-budget");
    let tree = root.join("node_modules/harness-cli");
    std::fs::create_dir_all(&tree).unwrap();
    for index in 0..=MAX_MASKS {
        std::fs::write(tree.join(format!("package-{index}.key")), "x").unwrap();
    }
    let mut request = input(&root, &["/bin/sh", "-c", "true"]);
    request.exec_roots = vec![root.join("node_modules")];
    let error = workspace_argv(&request).unwrap_err();
    assert_eq!(error.reason_code, PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE);
    assert!(error.message.contains("package tree"), "{}", error.message);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_script_outside_the_workspace_is_bound_read_only_as_that_one_file() {
    let root = root("script");
    std::fs::create_dir_all(root.join("scratch")).unwrap();
    let script = root.join("scratch/check.py");
    std::fs::write(&script, "print(1)\n").unwrap();
    let script_text = script.to_string_lossy().into_owned();
    let mut request = input(&root, &["/bin/sh", "-c", "python3 check.py"]);
    request.read_files = vec![script.clone()];
    let argv = workspace_argv(&request).unwrap();
    assert!(after(&argv, "--ro-bind", &script_text));
    assert!(after(&argv, &script_text, &script_text));
    assert!(!argv
        .iter()
        .any(|value| value == root.join("scratch").to_str().unwrap()));
    let directory = root.join("scratch");
    let link = root.join("scratch/link.py");
    std::os::unix::fs::symlink(&script, &link).unwrap();
    for refused in [
        directory,
        link,
        root.join("ws/inside.py"),
        root.join("scratch/missing.py"),
        PathBuf::from("check.py"),
    ] {
        let mut request = input(&root, &["true"]);
        request.read_files = vec![refused.clone()];
        assert!(workspace_argv(&request).is_err(), "{}", refused.display());
    }
}

#[test]
fn layers_must_be_outside_the_workspace() {
    let root = root("layers");
    let mut request = input(&root, &["true"]);
    request.upper = root.join("ws/upper");
    assert!(workspace_argv(&request).is_err());
    let mut request = input(&root, &["true"]);
    request.work = root.join("private/work");
    assert!(workspace_argv(&request).is_err());
    let mut request = input(&root, &["true"]);
    request.command.clear();
    assert!(workspace_argv(&request).is_err());
    let mut request = input(&root, &["true"]);
    request.backend_executable = root.join("ws");
    assert!(workspace_argv(&request).is_err());
}

#[test]
fn the_sandbox_confines_a_real_run_when_available() {
    if !available() {
        return;
    }
    let root = root("live");
    let ws = root.join("ws");
    std::fs::write(ws.join(".env"), "SECRET=1").unwrap();
    std::fs::write(ws.join("keep.txt"), "kept").unwrap();
    let (_, bwrap) = select_backend("linux", None, "/usr/bin:/bin").unwrap();
    let mut request = input(
        &root,
        &[
            "/bin/sh",
            "-c",
            &format!(
                "echo built > out.txt; rm keep.txt; cat .env; echo x > {}",
                root.join("escape").display()
            ),
        ],
    );
    request.backend_executable = bwrap;
    let argv = workspace_argv(&request).unwrap();
    let output = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SECRET"));
    assert_eq!(
        std::fs::read_to_string(ws.join("keep.txt")).unwrap(),
        "kept"
    );
    super::super::workspace_overlay::apply(&request.upper, &ws, &[]).unwrap();
    assert_eq!(
        std::fs::read_to_string(ws.join("out.txt")).unwrap(),
        "built\n"
    );
    assert!(!ws.join("keep.txt").exists());
    assert!(!root.join("escape").exists());
    super::remove_overlay_root(&root.join("overlay"));
}

#[test]
fn a_linked_worktree_reads_its_checkout_and_overlays_the_shared_git() {
    let root = root("linked");
    let main = root.join("main");
    std::fs::create_dir_all(main.join(".git/worktrees/ws")).unwrap();
    std::fs::create_dir_all(root.join("shared/upper")).unwrap();
    std::fs::create_dir_all(root.join("shared/work")).unwrap();
    std::fs::write(main.join(".env"), "SECRET=1").unwrap();
    let mut request = input(&root, &["/bin/sh", "-c", "git commit -m x"]);
    request.linked_git = Some(super::super::workspace_linked::LinkedGit {
        common: main.join(".git"),
        admin: main.join(".git/worktrees/ws"),
    });
    request.shared_upper = Some(root.join("shared/upper"));
    request.shared_work = Some(root.join("shared/work"));
    let argv = workspace_argv(&request).unwrap();
    let text = |path: PathBuf| path.to_string_lossy().into_owned();
    let position = |flag: &str, value: String| {
        argv.windows(2)
            .position(|pair| pair[0] == flag && pair[1] == value)
            .unwrap()
    };
    let checkout = position("--ro-bind", text(main.clone()));
    let shared = position("--overlay-src", text(main.join(".git")));
    let workspace = position("--overlay-src", text(root.join("ws")));
    assert!(checkout < shared && shared < workspace, "{argv:?}");
    assert!(
        after(&argv, "/dev/null", &text(main.join(".env"))),
        "{argv:?}"
    );
    // All three are required, and the layers stay apart from the run's own.
    request.shared_work = None;
    assert!(workspace_argv(&request).is_err());
    request.shared_work = Some(root.join("overlay/upper/work"));
    assert!(workspace_argv(&request).is_err());
    request.shared_work = Some(root.join("main/work"));
    assert!(workspace_argv(&request).is_err());
    let _ = std::fs::remove_dir_all(&root);
}
