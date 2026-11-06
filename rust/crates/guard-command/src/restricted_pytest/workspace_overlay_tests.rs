use super::*;

struct Layers {
    workspace: PathBuf,
    upper: PathBuf,
}

fn layers(name: &str) -> Layers {
    let root = std::env::temp_dir().join(format!("guard-ov-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let workspace = root.join("ws");
    let upper = root.join("upper");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&upper).unwrap();
    Layers {
        workspace: workspace.canonicalize().unwrap(),
        upper: upper.canonicalize().unwrap(),
    }
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[cfg(target_os = "linux")]
fn whiteout(path: &Path) {
    use nix::sys::stat::{mknod, Mode, SFlag};
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    // A 0/0 character device is the overlay whiteout, which unprivileged
    // users may create.
    mknod(path, SFlag::S_IFCHR, Mode::from_bits_truncate(0o600), 0).unwrap();
}

#[cfg(target_os = "linux")]
fn opaque(path: &Path) {
    fs::create_dir_all(path).unwrap();
    rustix::fs::lsetxattr(
        path,
        "user.overlay.opaque",
        b"y",
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
}

#[test]
fn ordinary_changes_are_applied() {
    let l = layers("ordinary");
    write(&l.workspace.join("a.txt"), "old");
    write(&l.workspace.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(&l.upper.join("a.txt"), "new");
    write(&l.upper.join("src/main.py"), "print(1)\n");
    write(&l.upper.join(".git/index"), "index");
    std::os::unix::fs::symlink("a.txt", l.upper.join("link")).unwrap();
    fs::set_permissions(l.upper.join("src"), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(apply(&l.upper, &l.workspace, &[]).unwrap(), 6);
    assert_eq!(
        fs::read_to_string(l.workspace.join("a.txt")).unwrap(),
        "new"
    );
    assert_eq!(
        fs::read_to_string(l.workspace.join("src/main.py")).unwrap(),
        "print(1)\n"
    );
    assert_eq!(
        fs::read_to_string(l.workspace.join(".git/index")).unwrap(),
        "index"
    );
    assert_eq!(
        fs::read_link(l.workspace.join("link")).unwrap(),
        Path::new("a.txt")
    );
    let mode = l.workspace.join("src").metadata().unwrap().mode() & 0o777;
    assert_eq!(mode, 0o755);
    let leftovers: Vec<_> = fs::read_dir(&l.workspace)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".hol-guard-")
        })
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn one_protected_change_discards_the_whole_run() {
    for (index, protected) in [
        ".git/hooks/pre-commit",
        ".git/config",
        "sub/.git/config",
        ".env",
        "config/.env.local",
        "deploy.key",
        ".ssh/id_ed25519",
        ".claude/settings.json",
        ".vscode/tasks.json",
        ".zcode/settings.json",
        ".opencode/plugins/x.ts",
        ".copilot/a",
        ".clinerules/rules.md",
        ".gemini/settings.json",
        ".github/copilot-instructions.md",
        "AGENTS.md",
        ".github/workflows/ci.yml",
        "tools/mon",
    ]
    .iter()
    .enumerate()
    {
        let l = layers(&format!("protected-{index}"));
        write(&l.workspace.join(".git/HEAD"), "ref: refs/heads/main\n");
        fs::create_dir_all(l.workspace.join(".git/hooks")).unwrap();
        write(&l.upper.join("ok.txt"), "x");
        write(&l.upper.join(protected), "x");
        let denials = [l.workspace.join("tools/mon")];
        let error = apply(&l.upper, &l.workspace, &denials).unwrap_err();
        assert_eq!(error.reason_code, WRITE_DENIED_REASON_CODE, "{protected}");
        assert!(!l.workspace.join("ok.txt").exists(), "{protected}");
    }
}

#[test]
fn creating_a_repository_entry_is_denied() {
    let l = layers("nested-git");
    fs::create_dir_all(l.upper.join("vendor/.git")).unwrap();
    assert!(apply(&l.upper, &l.workspace, &[]).is_err());
    assert!(!l.workspace.join("vendor").exists());
}

#[test]
fn a_planted_bare_repository_is_denied() {
    let l = layers("bare-head");
    write(&l.upper.join("vendor/x/HEAD"), "ref: refs/heads/main\n");
    write(&l.upper.join("vendor/x/config"), "[core]\n");
    assert!(apply(&l.upper, &l.workspace, &[]).is_err());
    assert!(!l.workspace.join("vendor").exists());
    let l = layers("own-head");
    write(&l.workspace.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(&l.upper.join(".git/HEAD"), "ref: refs/heads/feature\n");
    write(&l.upper.join(".git/logs/HEAD"), "0 1 commit: x\n");
    apply(&l.upper, &l.workspace, &[]).unwrap();
    let l = layers("nested-reflog");
    write(&l.upper.join("vendor/x/logs/HEAD"), "0 1 commit: x\n");
    assert!(apply(&l.upper, &l.workspace, &[]).is_err());
    // The reopened reflog may not gain the rest of a repository.
    for planted in [
        ".git/logs/objects/ab/cd",
        ".git/logs/config",
        ".git/refs/remotes/o/commondir",
    ] {
        let l = layers("reflog-repository");
        write(&l.workspace.join(".git/HEAD"), "ref: refs/heads/main\n");
        write(&l.upper.join(".git/logs/HEAD"), "0 1 commit: x\n");
        write(&l.upper.join(planted), "x");
        assert!(apply(&l.upper, &l.workspace, &[]).is_err(), "{planted}");
        assert!(!l.workspace.join(planted).exists(), "{planted}");
    }
    let l = layers("branch-reflog");
    write(&l.workspace.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(&l.upper.join(".git/logs/HEAD"), "0 1 commit: x\n");
    write(
        &l.upper.join(".git/logs/refs/heads/main"),
        "0 1 commit: x\n",
    );
    write(&l.upper.join(".git/refs/heads/main"), "0123\n");
    write(&l.upper.join(".git/refs/heads/fix/config"), "0123\n");
    apply(&l.upper, &l.workspace, &[]).unwrap();
    assert!(l.workspace.join(".git/refs/heads/fix/config").exists());
}

#[test]
fn replacing_a_directory_above_a_denial_is_denied() {
    let l = layers("denial-ancestor");
    write(&l.workspace.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(&l.workspace.join("tools/mon"), "safe");
    write(&l.upper.join("evil/mon"), "#!/bin/sh\n");
    std::os::unix::fs::symlink("evil", l.upper.join("tools")).unwrap();
    let denials = [l.workspace.join("tools/mon")];
    assert!(apply(&l.upper, &l.workspace, &denials).is_err());
    assert_eq!(
        fs::read_to_string(l.workspace.join("tools/mon")).unwrap(),
        "safe"
    );
    assert!(!l.workspace.join("evil").exists());
    // A sibling of the denial can still change.
    let l = layers("denial-sibling");
    write(&l.workspace.join("tools/mon"), "safe");
    write(&l.upper.join("tools/other.txt"), "x");
    let denials = [l.workspace.join("tools/mon")];
    apply(&l.upper, &l.workspace, &denials).unwrap();
    assert!(l.workspace.join("tools/other.txt").exists());
}

#[test]
fn a_file_replacing_a_directory_checks_what_it_removes() {
    let l = layers("replace-dir");
    write(&l.workspace.join("pkg/.git/config"), "[core]\n");
    write(&l.upper.join("pkg"), "file");
    assert!(apply(&l.upper, &l.workspace, &[]).is_err());
    assert!(l.workspace.join("pkg/.git/config").exists());
    let l = layers("replace-plain-dir");
    write(&l.workspace.join("build/out.js"), "x");
    write(&l.upper.join("build"), "file");
    apply(&l.upper, &l.workspace, &[]).unwrap();
    assert_eq!(
        fs::read_to_string(l.workspace.join("build")).unwrap(),
        "file"
    );
}

#[test]
fn special_files_are_refused() {
    let l = layers("fifo");
    nix::unistd::mkfifo(
        &l.upper.join("pipe"),
        nix::sys::stat::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    assert!(apply(&l.upper, &l.workspace, &[]).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn whiteouts_delete_and_check_the_removed_tree() {
    let l = layers("whiteout");
    write(&l.workspace.join("gone.txt"), "x");
    write(&l.workspace.join("dist/app.js"), "x");
    whiteout(&l.upper.join("gone.txt"));
    whiteout(&l.upper.join("dist"));
    assert_eq!(apply(&l.upper, &l.workspace, &[]).unwrap(), 2);
    assert!(!l.workspace.join("gone.txt").exists());
    assert!(!l.workspace.join("dist").exists());

    let l = layers("whiteout-repo");
    write(&l.workspace.join("sub/.git/hooks/post-checkout"), "x");
    write(&l.workspace.join("other.txt"), "x");
    whiteout(&l.upper.join("sub"));
    whiteout(&l.upper.join("other.txt"));
    assert!(apply(&l.upper, &l.workspace, &[]).is_err());
    assert!(l.workspace.join("sub/.git/hooks/post-checkout").exists());
    assert!(l.workspace.join("other.txt").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn opaque_directories_replace_their_lower_contents() {
    let l = layers("opaque");
    write(&l.workspace.join("d/old.txt"), "x");
    opaque(&l.upper.join("d"));
    write(&l.upper.join("d/new.txt"), "y");
    apply(&l.upper, &l.workspace, &[]).unwrap();
    assert!(!l.workspace.join("d/old.txt").exists());
    assert_eq!(
        fs::read_to_string(l.workspace.join("d/new.txt")).unwrap(),
        "y"
    );

    // A directory under an opaque one is recreated, even when the
    // workspace has a directory at that path.
    let l = layers("opaque-nested");
    write(&l.workspace.join("d/sub/old.txt"), "x");
    opaque(&l.upper.join("d"));
    write(&l.upper.join("d/sub/new.txt"), "y");
    apply(&l.upper, &l.workspace, &[]).unwrap();
    assert!(!l.workspace.join("d/sub/old.txt").exists());
    assert!(l.workspace.join("d/sub/new.txt").exists());

    let l = layers("opaque-repo");
    write(&l.workspace.join("d/.git/config"), "[core]\n");
    opaque(&l.upper.join("d"));
    assert!(apply(&l.upper, &l.workspace, &[]).is_err());
    assert!(l.workspace.join("d/.git/config").exists());
}

#[test]
fn requests_must_keep_the_layers_apart() {
    let l = layers("request");
    let reply = evaluate(
        "apply_workspace_overlay",
        &json!({"workspace": l.workspace, "upper": l.workspace.join("u"), "write_denials": []}),
    )
    .unwrap();
    assert_eq!(reply["reason_code"], PYTEST_INVALID_COMMAND_REASON_CODE);
    let reply = evaluate(
        "apply_workspace_overlay",
        &json!({"workspace": l.workspace, "upper": l.upper, "write_denials": [], "search_path": ""}),
    )
    .unwrap();
    assert_eq!(reply["value"]["applied"], 0);
}
