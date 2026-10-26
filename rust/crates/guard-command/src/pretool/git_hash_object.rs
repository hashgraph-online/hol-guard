//! Closed grammar for a `git hash-object` invocation that only prints the
//! object ids of existing files.
//!
//! Writing to the object database (`-w`), reading paths or content from
//! standard input, `--literally` and `--path` are outside this grammar and
//! stay reviewed. A clean filter is the only configured program the command
//! can run, so callers must prove no named file maps to a configured filter
//! unless `--no-filters` is set. Operands are passed to that attribute check
//! verbatim, so `~` spellings the shell would expand are refused.

/// The file operands of a read-only invocation. `arguments` are the tokens
/// after the `hash-object` subcommand. `None` when any token is outside the
/// grammar or no file is named.
pub(crate) fn read_operands(arguments: &[String]) -> Option<Vec<&str>> {
    let mut operands = Vec::new();
    let mut options = true;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if options && argument == "--" {
            options = false;
        } else if options && argument.starts_with('-') {
            match argument.as_str() {
                "--no-filters" => {}
                "-t" => {
                    if !arguments.get(index).is_some_and(|value| {
                        matches!(value.as_str(), "blob" | "commit" | "tree" | "tag")
                    }) {
                        return None;
                    }
                    index += 1;
                }
                _ => return None,
            }
        } else if argument.is_empty() || argument.starts_with([':', '~']) {
            return None;
        } else {
            operands.push(argument.as_str());
        }
    }
    (!operands.is_empty()).then_some(operands)
}

/// Whether `--no-filters` applies, so no clean filter can run.
pub(crate) fn filters_disabled(arguments: &[String]) -> bool {
    arguments
        .iter()
        .take_while(|argument| argument.as_str() != "--")
        .any(|argument| argument == "--no-filters")
}

/// Whether `arguments` only hash bounded, non-sensitive files. A clean filter
/// can run unless disabled, so that case needs the helper-context proof.
pub(super) fn safe_read(
    arguments: &[String],
    allow_helper_context: bool,
    context: super::PathContext<'_>,
) -> bool {
    (allow_helper_context || filters_disabled(arguments))
        && read_operands(arguments).is_some_and(|operands| {
            operands.iter().all(|operand| {
                !super::sensitive_read_path_argument(operand)
                    && super::safe_reads::bounded_read_target(
                        operand,
                        context.home_dir,
                        context.cwd,
                        false,
                    )
            })
        })
}
