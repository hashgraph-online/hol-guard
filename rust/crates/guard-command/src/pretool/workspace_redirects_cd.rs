//! A Python heredoc after a `cd` into the directory the hook already runs in.
//!
//! `python3 - <<'EOF'` with a body that imports modules runs in the workspace
//! sandbox when the interpreter is the whole command, because chained to
//! other commands the program could prepare what they run. Agents often
//! write `cd '<workspace>' && python3 - <<'EOF'` instead. A `cd` runs before
//! the program and starts nothing, so it cannot run what the program
//! prepares; the projection used to treat it as such a chain and the command
//! fell through to a block.
//!
//! The `cd` is taken only when its target is proved to be the directory the
//! hook reports. Every check on the raw text, such as which local modules
//! the program imports and what its relative paths reach, reads paths from
//! that directory, so a `cd` anywhere else would make them read the wrong
//! place.

use std::path::Path;

use serde_json::Value;

use crate::pretool::PathContext;

/// Whether `projected` is `cd <one word> && ` followed by the Python
/// interpreter fed on standard input, alone (`python_alone`). The word is
/// plain, or single or double quoted with nothing the shell expands inside.
pub(super) fn python_after_cd(projected: &str) -> bool {
    after_cd(projected).is_some_and(|program| {
        !program.contains('\n') && crate::pretool::script_content::fed::python_alone(program)
    })
}

/// The text after a leading `cd <one word> && `.
fn after_cd(text: &str) -> Option<&str> {
    split_cd(text).map(|(_, program)| program)
}

/// The directory a leading `cd <one word> && ` names, without its quotes, and
/// the text after it.
fn split_cd(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("cd ")?.trim_start_matches(' ');
    let (word, word_end) = match rest.chars().next()? {
        quote @ ('\'' | '"') => {
            let end = rest[1..].find(quote)?;
            (quote == '\'' || !rest[1..1 + end].contains(['$', '`', '\\']))
                .then_some((&rest[1..1 + end], end + 2))?
        }
        _ => rest
            .find(' ')
            .filter(|end| plain(&rest[..*end]))
            .map(|end| (&rest[..end], end))?,
    };
    let program = rest[word_end..]
        .trim_start_matches(' ')
        .strip_prefix("&&")?;
    Some((word, program.trim_start_matches(' ')))
}

/// Whether the leading `cd` of `projected` names `workspace` by its absolute
/// path. The sandbox runs from the workspace root, so that `cd` changes
/// nothing. A relative word could be moved by `CDPATH`, which the sandbox
/// cannot see, so it is not taken. Neither is a word with `..`: the shell's
/// logical `cd` drops the name before it, while canonicalizing first follows
/// that name if it is a link, so the two could reach different directories.
pub(super) fn enters_workspace(projected: &str, workspace: &Path) -> bool {
    split_cd(projected)
        .map(|(word, _)| Path::new(word))
        .filter(|target| {
            target.is_absolute()
                && !target
                    .components()
                    .any(|part| part == std::path::Component::ParentDir)
        })
        .and_then(|target| std::fs::canonicalize(target).ok())
        .zip(std::fs::canonicalize(workspace).ok())
        .is_some_and(|(target, root)| target == root)
}

/// The payload the raw text is reviewed from. Once the `cd` is proved to
/// enter the hook's directory it changes nothing, so the raw text is the
/// program after it, which earns the review the same program earns alone.
pub(super) fn reviewed_payload(payload: &Value, command: &str, entered: bool) -> Value {
    match after_cd(command).filter(|_| entered) {
        Some(program) => {
            super::super::command_rewrite::payload_with_command(payload, command, program)
        }
        None => payload.clone(),
    }
}

fn plain(word: &str) -> bool {
    !word.is_empty()
        && word
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || "._-/+@%,=:".contains(value))
}

/// Whether the leading `cd` of `projected` is proved to enter the directory
/// the hook reports.
pub(super) fn enters_cwd(projected: &str, context: PathContext<'_>) -> bool {
    let Some(cwd) = context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()) else {
        return false;
    };
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: projected.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "pre-tool-generic".to_owned(),
    })
    .ok()
    .filter(|model| model.confidence == "exact")
    .and_then(|model| crate::pretool::segment_proof::verified_leading_cd_target(&model, context))
    .is_some_and(|target| Path::new(&target) == cwd)
}

#[cfg(test)]
mod tests {
    use super::{enters_cwd, python_after_cd};
    use crate::pretool::PathContext;

    /// A program that imports modules, after a `cd`, projects only for
    /// `contained`, and only when the `cd` enters the hook's directory.
    #[test]
    fn a_cd_into_the_hook_directory_keeps_python_in_the_sandbox() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/narrower-sink-fixtures")
            .join(format!("python-after-cd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("project/sub")).unwrap();
        let root = root.canonicalize().unwrap();
        let ws = root.join("project");
        let cwd = ws.to_str().unwrap();
        let context = PathContext {
            home_dir: root.to_str(),
            cwd: Some(cwd),
            cdpath_unset: true,
            ..PathContext::default()
        };
        let body = "<<'EOF'\nimport os\nprint(os.getcwd())\nEOF";
        let entered = format!("cd '{cwd}' && python3 - {body}");
        assert_eq!(super::super::project(&entered), None, "{entered}");
        let (projected, _, _, cd) = super::super::project_scan(&entered).unwrap();
        assert!(cd, "{projected}");
        assert!(enters_cwd(&projected, context), "{projected}");
        for elsewhere in [
            format!("cd '{cwd}/sub' && python3 -"),
            format!("cd '{}' && python3 -", root.to_str().unwrap()),
            "cd sub && python3 -".to_owned(),
        ] {
            assert!(!enters_cwd(&elsewhere, context), "{elsewhere}");
        }
    }

    #[test]
    fn only_one_plain_word_and_then_python_alone_is_read() {
        for projected in [
            "cd '/work/my dir' && python3 -",
            "cd \"/work/src\" && python3",
            "cd /work/src && python3 -",
            "cd . && python3",
        ] {
            assert!(python_after_cd(projected), "{projected}");
        }
        for projected in [
            "python3 -",
            "cd && python3 -",
            "cd a b && python3 -",
            "cd $HOME && python3 -",
            "cd \"$HOME\" && python3 -",
            "cd \"`pwd`\" && python3 -",
            "cd 'a && python3 -",
            "cd a; python3 -",
            "cd a || python3 -",
            "cd a && python3 - && ls",
            "cd a && python3 -\nls",
            "cd a && sh -",
            "cd a && cd b && python3 -",
        ] {
            assert!(!python_after_cd(projected), "{projected}");
        }
    }
}
