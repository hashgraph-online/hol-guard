use super::*;

#[test]
fn uvx_reviews_installed_distribution_and_extra_packages() {
    for (command, expected) in [
        ("uvx --from evil-pkg http", vec!["evil-pkg"]),
        ("uvx --from=evil-pkg http", vec!["evil-pkg"]),
        ("uvx --with extra pkg", vec!["pkg", "extra"]),
        ("uvx -w extra pkg", vec!["pkg", "extra"]),
        ("uvx -w=extra pkg", vec!["pkg", "extra"]),
        ("uvx -wextra pkg", vec!["pkg", "extra"]),
        (
            "uvx --with=extra --with second pkg",
            vec!["pkg", "extra", "second"],
        ),
        ("uvx pkg --with tool-argument", vec!["pkg"]),
        ("uvx pkg -w tool-argument", vec!["pkg"]),
    ] {
        let intent = parse_package_intent(command, None, None, None, None)
            .expect("uvx must produce a package intent");
        assert!(intent
            .targets
            .iter()
            .all(|target| target.ecosystem == "pypi"));
        let names: Vec<_> = intent
            .targets
            .iter()
            .map(|target| target.package_name.as_deref().unwrap())
            .collect();
        assert_eq!(names, expected, "{command}");
    }
}

#[test]
fn cargo_git_ssh_source_userinfo_redacted_from_command() {
    let intent = parse_package_intent(
        "cargo install --git ssh://user:TOKEN@git.example.com/owner/repo.git",
        None,
        None,
        None,
        None,
    )
    .expect("cargo install intent");
    assert!(!intent.redacted_command.contains("TOKEN"));
    assert!(!intent.redacted_command.contains("user@"));
    assert!(!intent
        .redacted_command
        .contains("ssh://user:TOKEN@git.example.com/owner/repo.git"));
}

#[test]
fn control_labels() {
    assert_eq!(control_context_label(Some("&&")), "and");
    assert_eq!(control_context_label(Some("|&")), "pipe-stderr");
    assert_eq!(control_context_label(None), "end");
}

#[test]
fn source_redaction_preserves_git_identity_without_credentials() {
    let tokens = vec![
        "npm".to_owned(),
        "install".to_owned(),
        "git+https://GITHUB.com:443/owner/repo.git?token=secret#commit".to_owned(),
    ];
    assert_eq!(
        redact_local_source_tokens(&tokens),
        vec![
            "npm",
            "install",
            "git+https://GITHUB.com:443/owner/repo.git"
        ]
    );
    assert_eq!(
        redact_local_source_tokens(&["file:/private/project".to_owned()]),
        vec!["[REDACTED_URL]"]
    );
    assert_eq!(
        redact_local_source_tokens(&[
            "npm".to_owned(),
            "install".to_owned(),
            "git+ssh://git@github.com/owner/repo.git#commit".to_owned()
        ]),
        vec!["npm", "install", "git+ssh://github.com/owner/repo.git"]
    );
    assert_eq!(
        redact_local_source_tokens(&[
            "npm".to_owned(),
            "install".to_owned(),
            "git@github.com:owner/repo.git#commit".to_owned()
        ]),
        vec!["npm", "install", "git@github.com:owner/repo.git#commit"]
    );
    assert_eq!(
        redact_local_source_tokens(&[
            "pip".to_owned(),
            "install".to_owned(),
            "--index-url=https://user:password@example.com/simple".to_owned()
        ]),
        vec!["pip", "install", "[REDACTED_URL]"]
    );
    assert_eq!(
        redact_local_source_tokens(&[
            "npm".to_owned(),
            "install".to_owned(),
            "git+https://user:password@github.com/owner/repo.git".to_owned()
        ]),
        vec!["npm", "install", "[REDACTED_URL]"]
    );
}

// package_intent_parser.py `_redact_local_source_tokens`
#[test]
fn redact_local_source_tokens_hides_cargo_local_path() {
    let redacted = redacted_segment(&[
        "cargo".to_owned(),
        "add".to_owned(),
        "demo".to_owned(),
        "--path".to_owned(),
        "crates/demo".to_owned(),
    ]);
    assert!(redacted.contains(&"--path".to_owned()));
    assert!(!redacted.iter().any(|token| token == "crates/demo"));

    let flag_form = redacted_segment(&[
        "cargo".to_owned(),
        "add".to_owned(),
        "demo".to_owned(),
        "--path=crates/demo".to_owned(),
    ]);
    assert!(!flag_form.iter().any(|token| token.contains("crates/demo")));
}

#[test]
fn compound_package_install_survives_quoted_and_unquoted_heredocs() {
    for delimiter in ["EOF", "'EOF'", "\"EOF\""] {
        let command = format!("npm install lodash && bash <<{delimiter}\nrm -f important.txt\nEOF");
        let intent =
            parse_package_intent(&command, None, None, None, None).expect("package install intent");
        assert_eq!(intent.intent_kind, "install");
        assert_eq!(intent.targets.len(), 1);
        assert_eq!(intent.targets[0].package_name.as_deref(), Some("lodash"));
    }
}

fn which_fixture(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "guard_which_on_path_{label}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("empty")).unwrap();
    std::fs::create_dir_all(dir.join("bin")).unwrap();
    dir
}

#[cfg(unix)]
#[test]
fn which_on_path_searches_every_unix_path_entry() {
    use std::os::unix::fs::PermissionsExt;

    let dir = which_fixture("unix");
    let npx = dir.join("bin").join("npx");
    std::fs::write(&npx, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&npx, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}::{}",
        dir.join("empty").display(),
        dir.join("bin").display()
    );
    assert_eq!(
        which_on_path("npx", &path).as_deref(),
        Some(npx.to_string_lossy().as_ref())
    );
    assert_eq!(which_on_path("missing", &path), None);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn which_on_path_uses_windows_separator_and_launcher_extensions() {
    let dir = which_fixture("windows");
    // npm ships an extensionless POSIX shim next to the launchable `.cmd`.
    std::fs::write(dir.join("bin").join("npx"), "#!/bin/sh\n").unwrap();
    let npx_cmd = dir.join("bin").join("npx.cmd");
    std::fs::write(&npx_cmd, "@echo off\r\n").unwrap();
    let path = format!(
        "{};{}",
        dir.join("empty").display(),
        dir.join("bin").display()
    );
    let expected = npx_cmd.to_string_lossy().into_owned();
    assert_eq!(
        which_on_path("npx", &path).as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(
        which_on_path("npx.cmd", &path).as_deref(),
        Some(expected.as_str())
    );
    assert_eq!(which_on_path("missing", &path), None);
    // A direct path picks the launcher too, never the extensionless sh shim.
    let direct = dir.join("bin").join("npx").to_string_lossy().into_owned();
    assert_eq!(
        which_on_path(&direct, &path).as_deref(),
        Some(expected.as_str())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn path_for_resolution_keeps_unix_entries_and_anchors_relative_ones() {
    let cwd = Path::new("/work");
    assert_eq!(
        path_for_resolution("/usr/bin::bin", Some(cwd)),
        "/usr/bin:/work/.:/work/bin"
    );
}

#[cfg(windows)]
#[test]
fn path_for_resolution_keeps_windows_drive_letter_entries() {
    let cwd = Path::new(r"C:\work");
    assert_eq!(
        path_for_resolution(r"C:\tools\node;D:\bin", Some(cwd)),
        r"C:\tools\node;D:\bin"
    );
}
