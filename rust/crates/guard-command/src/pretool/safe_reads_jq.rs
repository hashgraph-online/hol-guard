//! The argument list of one bounded `jq` read: options that only shape the
//! output, the variables jq binds before the filter runs, the filter itself
//! and, when jq reads a file rather than stdin, that file.

use super::{command_read_target, jq_filter};

/// jq's options that only shape how the value read is parsed and printed.
/// Every option that names a filter file or a module directory — `-f`,
/// `--from-file`, `-L`, `--library-path` — is absent, and so are `--args`,
/// `--jsonargs` and the deprecated `--argfile`, so one of those is read as
/// the filter instead and fails the grammar.
const READ_ONLY_LONG_OPTIONS: &[&str] = &[
    "--ascii-output",
    "--compact-output",
    "--exit-status",
    "--join-output",
    "--monochrome-output",
    "--null-input",
    "--raw-input",
    "--raw-output",
    "--slurp",
    "--sort-keys",
    "--tab",
];

/// The short spellings of those options. jq accepts them clustered, as in
/// `jq -rc`, so each letter of a cluster is checked against this set.
const READ_ONLY_SHORT_OPTIONS: &str = "acejMnrRsS";

/// `--arg NAME VALUE` and `--argjson NAME JSON` bind `$NAME` to a value
/// written on the command line. jq holds it as a string or parses it as
/// JSON data, and nothing in it runs, so the filter may read the name back.
const VALUE_BINDINGS: &[&str] = &["--arg", "--argjson"];

/// `--slurpfile NAME FILE` and `--rawfile NAME FILE` bind `$NAME` to the
/// contents of a file. That is one more read, so FILE has to clear the same
/// read-target screen an input file does.
const FILE_BINDINGS: &[&str] = &["--slurpfile", "--rawfile"];

fn read_only_option(argument: &str) -> bool {
    match argument.strip_prefix('-') {
        Some(cluster) if !cluster.starts_with('-') => {
            !cluster.is_empty()
                && cluster
                    .chars()
                    .all(|flag| READ_ONLY_SHORT_OPTIONS.contains(flag))
        }
        _ => READ_ONLY_LONG_OPTIONS.contains(&argument),
    }
}

/// One jq run as its argument list spells it. Options and bindings come
/// first; the first word that is neither is the filter, and every word after
/// it is an input file.
struct Call<'a> {
    filter: usize,
    names: Vec<&'a str>,
    files: Vec<&'a str>,
    operands: &'a [String],
    null_input: bool,
}

fn call(arguments: &[String]) -> Option<Call<'_>> {
    let mut names = Vec::new();
    let mut files = Vec::new();
    let mut null_input = false;
    let mut index = 0;
    loop {
        let argument = arguments.get(index)?.as_str();
        if read_only_option(argument) {
            null_input |= argument == "--null-input"
                || (!argument.starts_with("--") && argument.contains('n'));
            index += 1;
            continue;
        }
        let file = FILE_BINDINGS.contains(&argument);
        if !file && !VALUE_BINDINGS.contains(&argument) {
            break;
        }
        let name = arguments.get(index + 1)?.as_str();
        let value = arguments.get(index + 2)?.as_str();
        if !jq_filter::variable_name(name) {
            return None;
        }
        if file {
            files.push(value);
        }
        names.push(name);
        index += 3;
    }
    Some(Call {
        filter: index,
        names,
        files,
        operands: &arguments[index + 1..],
        null_input,
    })
}

impl Call<'_> {
    fn filter_safe(&self, arguments: &[String]) -> bool {
        jq_filter::safe_filter_binding(&arguments[self.filter], &self.names)
    }

    /// Every file a binding names is a bounded read in its own right.
    fn bindings_readable(&self, context: super::super::PathContext<'_>) -> bool {
        self.files
            .iter()
            .all(|file| !file.starts_with('-') && command_read_target(file, context, false))
    }
}

/// `jq <filter> <file>` reads one bounded file through the same filter
/// grammar the stdin form admits. `jq -n <filter>` reads no input at all.
pub(in crate::pretool) fn safe_jq_file_arguments(
    arguments: &[String],
    context: super::super::PathContext<'_>,
) -> bool {
    let Some(call) = call(arguments) else {
        return false;
    };
    let input = match call.operands {
        [] => call.null_input,
        [file] => !file.starts_with('-') && command_read_target(file, context, false),
        _ => false,
    };
    input && call.bindings_readable(context) && call.filter_safe(arguments)
}

/// Where a proven jq filter sits in the argument list. The filter is a
/// program over the value read, so a field such as `.key` is not a path to
/// screen.
pub(in crate::pretool) fn jq_filter_position(
    arguments: &[String],
    piped_input: bool,
) -> Option<usize> {
    let call = call(arguments)?;
    (call.operands.len() <= usize::from(!piped_input) && call.filter_safe(arguments))
        .then_some(call.filter)
}

/// `... | jq <filter>` reads the value the pipeline already produced.
///
/// Stdin may come from a network read the sandbox cannot contain, so the
/// filter still has to clear the grammar in full. It no longer has to open
/// with a projection: `length`, `map(.name)` and `select(.draft)` read the
/// same value `.items | length` does, and the grammar — not the leading
/// character — is what keeps a filter from reaching the environment, further
/// input, files or modules. With no path context to screen a file against,
/// a binding that reads one is refused here.
pub(in crate::pretool) fn safe_jq_stdin_arguments(arguments: &[String]) -> bool {
    call(arguments).is_some_and(|call| {
        call.operands.is_empty() && call.files.is_empty() && call.filter_safe(arguments)
    })
}

/// The stdin form where a path context is known, so `--slurpfile` and
/// `--rawfile` may name a file that clears the read-target screen.
pub(in crate::pretool) fn safe_jq_piped_arguments(
    arguments: &[String],
    context: super::super::PathContext<'_>,
) -> bool {
    call(arguments).is_some_and(|call| {
        call.operands.is_empty() && call.bindings_readable(context) && call.filter_safe(arguments)
    })
}
