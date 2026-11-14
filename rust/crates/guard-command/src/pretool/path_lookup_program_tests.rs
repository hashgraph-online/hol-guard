use super::{bare_name_model, first_path_match};

fn model(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}

fn environment(path: &str) -> guard_contracts::GuardExecutionEnvironmentV1 {
    guard_contracts::GuardExecutionEnvironmentV1 {
        path: path.to_owned(),
        environment_digest: "0".repeat(64),
        ..Default::default()
    }
}

#[cfg(unix)]
#[test]
fn only_the_first_absolute_match_is_renamed_and_nothing_else_moves() {
    let ls = std::fs::canonicalize("/bin/ls").unwrap();
    let directory = ls.parent().unwrap().to_str().unwrap().to_owned();
    let program = format!("{directory}/ls");
    assert_eq!(
        first_path_match(&program, &directory),
        Some("ls".to_owned())
    );
    assert_eq!(first_path_match("ls", &directory), None);
    assert_eq!(
        first_path_match(&format!("{directory}/../bin/ls"), &directory),
        None
    );
    assert_eq!(first_path_match(&program, &format!(":{directory}")), None);
    assert_eq!(
        first_path_match(&program, "/nonexistent-guard-folder"),
        None
    );

    let stamped = environment(&directory);
    let command = format!("cat -n {program} && {program} -d . | wc -l");
    let rewritten = bare_name_model(&model(&command), Some(&stamped)).unwrap();
    assert_eq!(
        rewritten.normalized_text,
        format!("cat -n {program} && ls -d . | wc -l")
    );
    let executables: Vec<_> = rewritten
        .segments
        .iter()
        .map(|segment| segment.executable.as_deref().unwrap())
        .collect();
    assert_eq!(executables, ["cat", "ls", "wc"]);
    assert_eq!(rewritten.segments[0].arguments, ["-n", program.as_str()]);

    assert!(bare_name_model(&model("ls -d ."), Some(&stamped)).is_none());
    assert!(bare_name_model(&model(&command), None).is_none());
}

#[cfg(unix)]
#[test]
fn shell_builtins_do_not_borrow_trust_from_path_executables() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("guard-path-builtin-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for name in [
        "pwd", "echo", "test", "true", "false", "which", "whence", "where", "print",
    ] {
        let file = root.join(name);
        std::fs::write(&file, "#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&file).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&file, permissions).unwrap();
        assert_eq!(
            first_path_match(file.to_str().unwrap(), root.to_str().unwrap()),
            None,
            "{name} is a shell builtin, not a PATH lookup"
        );
    }
    std::fs::remove_dir_all(&root).unwrap();
}
