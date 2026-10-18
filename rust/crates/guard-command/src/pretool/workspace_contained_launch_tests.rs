use super::*;

fn places(command: &str, program: &str, cdpath_unset: bool) -> Vec<Option<PathBuf>> {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();
    launches(&model, Path::new("/work/project"), cdpath_unset)
        .into_iter()
        .find(|(name, _)| *name == program)
        .unwrap_or_else(|| panic!("{program} is not launched by {command}"))
        .1
}

fn workspace() -> Option<PathBuf> {
    Some(PathBuf::from("/work/project"))
}

fn below(directory: &str) -> Option<PathBuf> {
    Some(PathBuf::from("/work/project").join(directory))
}

#[test]
fn a_cd_moves_the_launches_after_it_and_not_the_ones_before() {
    assert_eq!(places("./a && cd tools && ./b", "./a", true), [workspace()]);
    // The `cd` may fail, or run in a pipeline, and leave the shell in place.
    assert_eq!(
        places("cd tools && ./b", "./b", true),
        [workspace(), below("tools")]
    );
    assert_eq!(
        places("cd tools; cd more; ./b", "./b", true),
        [
            workspace(),
            below("tools"),
            below("more"),
            below("tools/more")
        ]
    );
}

#[test]
fn a_cd_is_not_a_launch() {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: "cd tools && pushd more && popd".to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();

    assert!(launches(&model, Path::new("/work/project"), true).is_empty());
}

#[test]
fn a_shell_builtin_is_not_a_launch() {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: "echo start && printf x; test -f a && ./run.sh || true".to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();

    let names: Vec<&str> = launches(&model, Path::new("/work/project"), true)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names, ["./run.sh"]);
}

#[test]
fn a_directory_no_literal_names_is_unknown() {
    let absolute = Some(PathBuf::from("/work/project/abs"));
    assert_eq!(
        places("cd /work/project/abs && ./b", "./b", true),
        [workspace(), absolute]
    );
    for command in [
        "cd ~/tools && ./b",
        "cd .. && ./b",
        "cd - && ./b",
        "cd && ./b",
        "cd -P tools && ./b",
        "cd $TOOLS && ./b",
        "cd /hol-guard-substituted/temporary-path && ./b",
    ] {
        assert_eq!(
            places(command, "./b", true),
            [workspace(), None],
            "{command}"
        );
    }
    assert_eq!(places("popd && ./b", "./b", true), [None]);
    // A search path can send a relative `cd` anywhere.
    assert_eq!(places("cd tools && ./b", "./b", false), [workspace(), None]);
}

#[test]
fn many_directory_changes_leave_the_position_unknown() {
    let command = format!("{}./b", "cd a; cd b; ".repeat(3));

    assert_eq!(places(&command, "./b", true), [None]);
}
