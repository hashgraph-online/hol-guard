use super::*;

use std::os::unix::fs::symlink;

struct Workspace {
    _root: tempfile::TempDir,
    base: PathBuf,
    repository: PathBuf,
    cwd: PathBuf,
}

/// A repository with a `.git` directory and a working directory two levels
/// below it, all under a canonical temporary root.
fn workspace() -> Workspace {
    let root = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(root.path()).unwrap();
    let repository = base.join("repository");
    let cwd = repository.join("workspace").join("service");
    fs::create_dir_all(&cwd).unwrap();
    fs::create_dir(repository.join(".git")).unwrap();
    fs::write(repository.join(".git/HEAD"), "ref: refs/heads/test\n").unwrap();
    Workspace {
        _root: root,
        base,
        repository,
        cwd,
    }
}

fn argv(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn run(workspace: &Workspace, values: &[&str]) -> Outcome<ReadOutcome> {
    execute(&argv(values), workspace.cwd.to_str().unwrap(), None)
}

#[test]
fn pwd_returns_the_working_directory_silently_verified() {
    let workspace = workspace();
    let outcome = run(&workspace, &["pwd"]).unwrap();
    assert_eq!(outcome.operation_id, "working-directory");
    assert_eq!(outcome.stdout, format!("{}\n", workspace.cwd.display()));
    assert_eq!(outcome.binding_digest.len(), 64);
    assert_eq!(outcome.decision["disposition"], "silent-verified");
    assert_eq!(outcome.decision["action"], "allow");
}

#[test]
fn each_read_shows_only_the_slice_the_plan_allows() {
    let workspace = workspace();
    let text: String = (1..=10).map(|number| format!("line{number}\n")).collect();
    fs::write(workspace.cwd.join("main.py"), text).unwrap();
    let view = run(&workspace, &["sed", "-n", "3,5p", "main.py"]).unwrap();
    assert_eq!(view.operation_id, "bounded-source-view");
    assert_eq!(view.stdout, "line3\nline4\nline5\n");
    let leading = run(&workspace, &["head", "--lines=2", "main.py"]).unwrap();
    assert_eq!(leading.operation_id, "bounded-head");
    assert_eq!(leading.stdout, "line1\nline2\n");
    let trailing = run(&workspace, &["tail", "-2", "main.py"]).unwrap();
    assert_eq!(trailing.operation_id, "bounded-tail");
    assert_eq!(trailing.stdout, "line9\nline10\n");
    let past_end = run(&workspace, &["sed", "-n", "9,40p", "main.py"]).unwrap();
    assert_eq!(past_end.stdout, "line9\nline10\n");
}

#[test]
fn the_proof_binds_the_output() {
    let workspace = workspace();
    fs::write(workspace.cwd.join("main.py"), "one\ntwo\n").unwrap();
    let first = run(&workspace, &["head", "-1", "main.py"]).unwrap();
    let both = run(&workspace, &["head", "-2", "main.py"]).unwrap();
    assert_ne!(first.binding_digest, both.binding_digest);
    assert_eq!(first.decision["disposition"], "silent-verified");
    assert_eq!(both.decision["disposition"], "silent-verified");
}

#[test]
fn shell_composition_traversal_symlinks_and_secrets_are_refused() {
    let workspace = workspace();
    fs::write(workspace.cwd.join("main.py"), "print('ok')\n").unwrap();
    fs::write(workspace.base.join("outside.py"), "private\n").unwrap();
    symlink(
        workspace.base.join("outside.py"),
        workspace.cwd.join("linked.py"),
    )
    .unwrap();
    fs::write(workspace.cwd.join(".env"), "TOKEN=x\n").unwrap();
    assert!(run(&workspace, &["head", "-40", "main.py"]).is_ok());
    for refused in [
        &["head", "-40", "linked.py"][..],
        &["head", "-40", "../outside.py"],
        &["head -40 main.py"],
        &["head", "-1001", "main.py"],
        &["head", "-40", ".env"],
        &["cat", "main.py"],
    ] {
        assert_eq!(
            run(&workspace, refused).unwrap_err(),
            Failure::Refused,
            "{refused:?}"
        );
    }
}

#[test]
fn a_directory_outside_any_checkout_is_not_a_workspace() {
    let workspace = workspace();
    let outside = workspace.base.join("plain");
    fs::create_dir(&outside).unwrap();
    let result = execute(&argv(&["pwd"]), outside.to_str().unwrap(), None);
    assert_eq!(result.unwrap_err(), Failure::Unavailable);
}

#[test]
fn a_working_directory_reached_through_a_symlink_is_not_canonical() {
    let workspace = workspace();
    let alias = workspace.base.join("alias");
    symlink(&workspace.cwd, &alias).unwrap();
    let result = execute(&argv(&["pwd"]), alias.to_str().unwrap(), None);
    assert_eq!(result.unwrap_err(), Failure::Unavailable);
    let relative = execute(&argv(&["pwd"]), "repository", None);
    assert_eq!(relative.unwrap_err(), Failure::Unavailable);
}

#[test]
fn a_git_marker_that_is_a_symlink_does_not_identify_a_checkout() {
    let workspace = workspace();
    let real = workspace.base.join("real.git");
    fs::rename(workspace.repository.join(".git"), &real).unwrap();
    symlink(&real, workspace.repository.join(".git")).unwrap();
    assert_eq!(run(&workspace, &["pwd"]).unwrap_err(), Failure::Unavailable);
}

#[test]
fn a_parent_swapped_for_a_symlink_after_resolution_is_not_followed() {
    let workspace = workspace();
    let safe = workspace.cwd.join("safe");
    fs::create_dir(&safe).unwrap();
    fs::write(safe.join("main.py"), "safe\n").unwrap();
    let outside = workspace.base.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("main.py"), "private\n").unwrap();
    let context = workspace_context(&workspace.cwd).unwrap();
    let target = resolve_target("safe/main.py", &context, None, deadline()).unwrap();
    fs::rename(&safe, workspace.cwd.join("safe-original")).unwrap();
    symlink(&outside, &safe).unwrap();
    let relative = target.strip_prefix(&context.repository).unwrap();
    assert_eq!(
        open_beneath_repository(relative, &context).unwrap_err(),
        Failure::Unavailable
    );
}

#[test]
fn a_replaced_repository_is_not_read_beneath() {
    let workspace = workspace();
    fs::write(workspace.cwd.join("main.py"), "safe\n").unwrap();
    let mut context = workspace_context(&workspace.cwd).unwrap();
    context.repository_file_identity.1 ^= 1;
    let relative = Path::new("workspace/service/main.py");
    assert_eq!(
        open_beneath_repository(relative, &context).unwrap_err(),
        Failure::Unavailable
    );
}

#[test]
fn hard_links_sockets_and_non_utf8_targets_are_not_read() {
    let workspace = workspace();
    fs::write(workspace.cwd.join("main.py"), "safe\n").unwrap();
    fs::hard_link(workspace.cwd.join("main.py"), workspace.cwd.join("twin.py")).unwrap();
    fs::write(workspace.cwd.join("binary.py"), [0xff, 0xfe, b'\n']).unwrap();
    // macOS caps a bound socket path at 104 bytes, which a temporary
    // directory plus this workspace's own depth already reaches, so bind the
    // socket under a short root and move it into place.
    let short = tempfile::Builder::new()
        .prefix("g")
        .tempdir_in("/tmp")
        .unwrap();
    let bound = short.path().join("s");
    let _socket = std::os::unix::net::UnixListener::bind(&bound).unwrap();
    fs::rename(&bound, workspace.cwd.join("socket.py")).unwrap();
    for name in ["main.py", "twin.py", "binary.py", "socket.py"] {
        assert_eq!(
            run(&workspace, &["head", "-1", name]).unwrap_err(),
            Failure::Unavailable,
            "{name}"
        );
    }
}

#[test]
fn output_past_the_bound_fails_closed() {
    let workspace = workspace();
    fs::write(
        workspace.cwd.join("wide.txt"),
        "x".repeat(MAX_OUTPUT_BYTES + 1),
    )
    .unwrap();
    assert_eq!(
        run(&workspace, &["head", "-1", "wide.txt"]).unwrap_err(),
        Failure::Unavailable
    );
}

#[test]
fn a_regular_file_past_its_bound_is_not_read() {
    let workspace = workspace();
    let path = workspace.cwd.join("grown.txt");
    fs::write(&path, "safe\nprivate-data\n").unwrap();
    assert!(read_regular_file_raw(&path, 8).is_err());
    assert_eq!(read_regular_file_raw(&path, 64).unwrap().len(), 18);
    assert_eq!(
        read_regular_file_raw(&workspace.cwd.join("absent"), 64)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound
    );
}

#[test]
fn a_bound_git_worktree_identifies_its_checkout() {
    let root = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(root.path()).unwrap();
    let repository = base.join("worktree");
    let cwd = repository.join("service");
    let common = base.join("common.git");
    let git_directory = common.join("worktrees").join("feature");
    fs::create_dir_all(&cwd).unwrap();
    fs::create_dir_all(&git_directory).unwrap();
    fs::write(git_directory.join("HEAD"), "ref: refs/heads/feature\n").unwrap();
    fs::write(git_directory.join("commondir"), "../..\n").unwrap();
    fs::write(common.join("config"), "[core]\n\tbare = false\n").unwrap();
    fs::write(
        repository.join(".git"),
        format!("gitdir: {}\n", git_directory.display()),
    )
    .unwrap();
    let outcome = execute(&argv(&["pwd"]), cwd.to_str().unwrap(), None).unwrap();
    assert_eq!(outcome.stdout, format!("{}\n", cwd.display()));

    fs::write(git_directory.join("commondir"), "../..\nextra\n").unwrap();
    assert_eq!(
        execute(&argv(&["pwd"]), cwd.to_str().unwrap(), None).unwrap_err(),
        Failure::Unavailable
    );
}

#[test]
fn the_gitdir_marker_matches_only_its_one_line_shape() {
    assert_eq!(gitdir_line("gitdir: ../x\n"), Some("../x"));
    assert_eq!(gitdir_line("gitdir: ../x\r\n"), Some("../x"));
    assert_eq!(gitdir_line("gitdir: ../x\r"), Some("../x"));
    assert_eq!(gitdir_line("gitdir: ../x"), Some("../x"));
    assert_eq!(gitdir_line("gitdir: \n"), None);
    assert_eq!(gitdir_line("gitdir: a\nb\n"), None);
    assert_eq!(gitdir_line("gitdir: a\n\n"), None);
    assert_eq!(gitdir_line("gitdir:a\n"), None);
}

#[test]
fn a_loosely_spelled_working_directory_is_not_read() {
    let workspace = workspace();
    let canonical = workspace.cwd.to_str().unwrap().to_owned();
    for cwd in [
        format!("{canonical}/"),
        canonical.replacen("/service", "/./service", 1),
        canonical.replacen("/service", "//service", 1),
    ] {
        assert_eq!(
            execute(&argv(&["pwd"]), &cwd, None).unwrap_err(),
            Failure::Unavailable,
            "{cwd}"
        );
    }
}

fn deadline() -> Instant {
    Instant::now() + EXECUTION_BUDGET
}

/// The resident's workers are shared, so a read that has already spent its
/// budget gives the worker back instead of finishing the file.
#[test]
fn a_read_past_its_budget_gives_up_the_worker() {
    let workspace = workspace();
    fs::write(workspace.cwd.join("main.py"), "one\ntwo\n").unwrap();
    let context = workspace_context(&workspace.cwd).unwrap();
    assert_eq!(
        read_target("main.py", &context, None, Instant::now()).unwrap_err(),
        Failure::Unavailable
    );
    assert!(read_target("main.py", &context, None, deadline()).is_ok());
}
