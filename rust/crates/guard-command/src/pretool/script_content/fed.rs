//! Whether a program's source needs the network or names a credential
//! store, however it reached the interpreter: a script file, or text fed on
//! standard input.

use super::{code_lines, python_network, Language, CREDENTIAL_STORE, NODE_NETWORK};

/// Whether `source` needs neither the network nor a credential store, the
/// bar a script launched in the workspace sandbox has to meet.
pub(in crate::pretool) fn source_clean(language: Language, source: &str) -> bool {
    let code = code_lines(language, source);
    let network = match language {
        Language::Python => python_network(&code),
        Language::Node => NODE_NETWORK.is_match(&code),
    };
    !network && !CREDENTIAL_STORE.is_match(&code)
}

/// Whether the projected command is only the Python interpreter, or that
/// interpreter piped to `tee` with plain file operands. A program that does
/// more than builtins can is held to the script-file bar only there: chained
/// to other commands it could prepare what they run, so a chain keeps the
/// builtin-only bar.
pub(in crate::pretool) fn python_alone(projected: &str) -> bool {
    let (head, tail) = match projected.split_once('|') {
        Some((head, tail)) => (head, Some(tail.trim())),
        None => (projected, None),
    };
    crate::native_command_controls::python_stdin(head.trim())
        && tail.is_none_or(|tail| {
            tail.strip_prefix("tee ").is_some_and(|files| {
                !files.trim().is_empty()
                    && !files.contains(|c: char| ";&|<>$`(){}\n\\'\"*?[~".contains(c))
            })
        })
}

/// Whether a program the POSIX shell text `command` launches needs the
/// network or names a credential store, counting the local modules it
/// imports. Neither is available in the workspace sandbox, so a program fed
/// on standard input that does either, itself or through `import helper`,
/// keeps the review of the text as sent.
pub(in crate::pretool) fn text_needs_withheld(
    command: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .is_ok_and(|model| {
        super::assess(&model, context)
            .iter()
            .any(|found| found.network || found.credential_store)
    })
}
