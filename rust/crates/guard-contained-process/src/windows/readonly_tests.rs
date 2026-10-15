use super::*;
use std::time::Duration;

/// LPAC can read only installed runtimes; a per-user interpreter is not usable.
fn installed_python() -> Option<PathBuf> {
    guard_runtime_windows_process::trusted_install_roots()
        .into_iter()
        .filter_map(|root| fs::read_dir(root).ok())
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .starts_with("python3")
        })
        .map(|entry| entry.path().join("python.exe"))
        .find(|path| path.is_file())
}

fn workspace() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let workspace = PathBuf::from(
        directory
            .path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .trim_start_matches(r"\\?\"),
    );
    fs::write(workspace.join("visible.txt"), "visible-sentinel").unwrap();
    fs::write(workspace.join(".env"), "TOKEN=withheld-sentinel").unwrap();
    fs::create_dir(workspace.join("nested")).unwrap();
    fs::write(workspace.join("nested").join("inner.txt"), "inner-sentinel").unwrap();
    (directory, workspace)
}

fn run_python(workspace: &Path, code: &str, timeout: Duration) -> Option<CapturedOutput> {
    let Some(python) = installed_python() else {
        eprintln!("skipped: no Python installed under Program Files");
        return None;
    };
    let cancel = AtomicBool::new(false);
    let arguments = [
        OsString::from("-I"),
        OsString::from("-c"),
        OsString::from(code),
    ];
    let environment: Vec<(OsString, OsString)> = ["SystemRoot", "PATH", "PATHEXT"]
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| ((*name).into(), value)))
        .collect();
    let withhold = |path: &Path| path.file_name().is_some_and(|name| name == ".env");
    Some(
        run_readonly_snapshot(ReadonlySnapshotRun {
            workspace,
            cwd: workspace,
            executable: &python,
            arguments: &arguments,
            environment: &environment,
            withhold: &withhold,
            max_entries: 100,
            max_bytes: 1024 * 1024,
            output_cap: 64 * 1024,
            deadline: Instant::now() + timeout,
            cancel: &cancel,
            job_limits: guard_runtime_windows_process::ResourceLimits {
                active_processes: Some(8),
                ..Default::default()
            },
        })
        .unwrap(),
    )
}

fn checked(workspace: &Path, code: &str) -> Option<String> {
    let output = run_python(workspace, code, Duration::from_secs(60))?;
    assert_eq!(
        output.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[test]
fn snapshot_files_are_readable() {
    let (_directory, workspace) = workspace();
    let code = "print(open('visible.txt').read(), open('nested/inner.txt').read())";
    if let Some(stdout) = checked(&workspace, code) {
        assert!(
            stdout.contains("visible-sentinel inner-sentinel"),
            "{stdout}"
        );
    }
}

#[test]
fn withheld_files_never_enter_the_snapshot() {
    let (_directory, workspace) = workspace();
    if let Some(stdout) = checked(&workspace, "import os; print(os.path.exists('.env'))") {
        assert_eq!(stdout.trim(), "False");
    }
}

#[test]
fn snapshot_and_live_workspace_stay_unwritten() {
    let (_directory, workspace) = workspace();
    let live = workspace.join("visible.txt");
    let code = format!(
        "denied = 0\nfor path in ['visible.txt', 'new.txt', r'{}']:\n    try:\n        open(path, 'w').write('changed')\n    except PermissionError:\n        denied += 1\nprint(denied)",
        live.display()
    );
    if let Some(stdout) = checked(&workspace, &code) {
        assert_eq!(stdout.trim(), "3");
    }
    assert_eq!(fs::read_to_string(&live).unwrap(), "visible-sentinel");
    assert!(!workspace.join("new.txt").exists());
}

#[test]
fn profile_files_outside_the_snapshot_are_unreadable() {
    let (_directory, workspace) = workspace();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret.txt");
    fs::write(&secret, "profile-sentinel").unwrap();
    let code = format!(
        "try:\n    print(open(r'{}').read())\nexcept PermissionError:\n    print('denied')",
        secret.display()
    );
    if let Some(stdout) = checked(&workspace, &code) {
        assert_eq!(stdout.trim(), "denied");
    }
}

#[test]
fn private_temp_is_writable() {
    let (_directory, workspace) = workspace();
    let code = "import tempfile\nwith tempfile.NamedTemporaryFile('w', delete=False) as f: f.write('x')\nprint('hol-guard-readonly-' in f.name)";
    if let Some(stdout) = checked(&workspace, code) {
        assert_eq!(stdout.trim(), "True");
    }
}

#[test]
fn installed_extension_modules_load() {
    let (_directory, workspace) = workspace();
    let code = "import _testinternalcapi, select, unicodedata\nprint('loaded')";
    if let Some(stdout) = checked(&workspace, code) {
        assert_eq!(stdout.trim(), "loaded");
    }
}

#[test]
fn user_registry_is_unreadable() {
    let (_directory, workspace) = workspace();
    let code = "import winreg\ntry:\n    winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment')\n    print('read')\nexcept PermissionError:\n    print('denied')";
    if let Some(stdout) = checked(&workspace, code) {
        assert_eq!(stdout.trim(), "denied");
    }
}

/// Without a registry capability Winsock cannot even start, which is stricter
/// than a denied connection; either outcome leaves the network unreachable.
#[test]
fn network_is_unavailable() {
    let (_directory, workspace) = workspace();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let code = format!(
        "try:\n    import socket\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\n    print('connected')\nexcept (ImportError, OSError):\n    print('denied')"
    );
    if let Some(stdout) = checked(&workspace, &code) {
        assert_eq!(stdout.trim(), "denied");
    }
}

#[test]
fn deadline_kills_the_process() {
    let (_directory, workspace) = workspace();
    let started = Instant::now();
    if let Some(output) = run_python(
        &workspace,
        "import time; time.sleep(60)",
        Duration::from_secs(3),
    ) {
        assert!(output.timed_out, "{output:?}");
        assert!(started.elapsed() < Duration::from_secs(30));
    }
}

#[test]
fn snapshot_budget_fails_closed() {
    let (_directory, workspace) = workspace();
    for index in 0..120 {
        fs::write(workspace.join(format!("f{index}.txt")), "x").unwrap();
    }
    let cancel = AtomicBool::new(false);
    let withhold = |_: &Path| false;
    let result = run_readonly_snapshot(ReadonlySnapshotRun {
        workspace: &workspace,
        cwd: &workspace,
        executable: Path::new(r"C:\Windows\System32\cmd.exe"),
        arguments: &[],
        environment: &[],
        withhold: &withhold,
        max_entries: 100,
        max_bytes: 1024 * 1024,
        output_cap: 1024,
        deadline: Instant::now() + Duration::from_secs(60),
        cancel: &cancel,
        job_limits: Default::default(),
    });
    assert!(result.is_err());
}

#[test]
fn hardlinked_files_fail_closed() {
    let (_directory, workspace) = workspace();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("credentials");
    fs::write(&secret, "linked-sentinel").unwrap();
    fs::hard_link(&secret, workspace.join("notes.txt")).unwrap();
    let cancel = AtomicBool::new(false);
    let withhold = |_: &Path| false;
    let result = run_readonly_snapshot(ReadonlySnapshotRun {
        workspace: &workspace,
        cwd: &workspace,
        executable: Path::new(r"C:\Windows\System32\cmd.exe"),
        arguments: &[],
        environment: &[],
        withhold: &withhold,
        max_entries: 100,
        max_bytes: 1024 * 1024,
        output_cap: 1024,
        deadline: Instant::now() + Duration::from_secs(60),
        cancel: &cancel,
        job_limits: Default::default(),
    });
    assert!(result.is_err());
}
