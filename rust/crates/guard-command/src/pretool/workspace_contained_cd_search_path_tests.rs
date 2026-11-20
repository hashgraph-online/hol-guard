use crate::CommandModelRequestV1;

fn sets_search_path(command: &str) -> bool {
    let model = crate::parse_command(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "pre-tool-generic".into(),
    })
    .unwrap();
    model.segments.iter().any(super::sets_search_path)
}

/// Every spelling that gives the shell a directory list to search before the
/// current directory, so a bare relative `cd` operand can land outside the
/// workspace the shape reads it against.
#[test]
fn every_spelling_of_a_directory_search_path_is_seen() {
    for command in [
        "CDPATH=/ cd etc && ls",
        "CDPATH=/etc:/var cd default && cat passwd",
        "export CDPATH=/ && cd etc && ls",
        "export CDPATH=/",
        // zsh ties the same search to a lowercase `cdpath`, and `export`
        // there sets both spellings at once.
        "cdpath=/ cd etc && ls",
        "export cdpath=/ && cd etc && ls",
        "CdPath=/ cd etc && ls",
        "declare -x CDPATH=/ && cd etc && ls",
        "typeset -x cdpath=/ && cd etc && ls",
        "setenv CDPATH / && cd etc && ls",
        // `readonly` and `local` set the variable as much as `export` does.
        "readonly CDPATH=/ && cd etc && ls",
        "local cdpath=/ && cd etc && ls",
        // Appending to an unset variable sets it, so the name is read with
        // the `+` off, wherever the assignment stands.
        "export CDPATH+=/ && cd etc && ls",
        "CDPATH+=/ cd etc && ls",
        "declare -x cdpath+=/ && cd etc && ls",
    ] {
        assert!(sets_search_path(command), "{command}");
    }
}

/// The screen reads what a segment sets, not what it says. A command that
/// only names the variable — searching for it, printing it, writing it into a
/// file — hands the shell no list, so containment still has to admit it.
#[test]
fn naming_the_variable_is_not_setting_it() {
    for command in [
        "cd app && ls",
        "grep -rn cdpath docs",
        "rg CDPATH rust/crates",
        "echo CDPATH=/ >> notes.md",
        "cat .config/cdpath.toml",
        // A different variable with the name inside it is its own name.
        "MY_CDPATH=/ cd app && ls",
        "export CDPATH_NOTES=1 && cd app && ls",
        "CDPATH_NOTES+=1 cd app && ls",
        // Git's roots are screened separately, not here.
        "GIT_DIR=.git cd app && ls",
    ] {
        assert!(!sets_search_path(command), "{command}");
    }
}
