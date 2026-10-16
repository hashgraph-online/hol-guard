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
