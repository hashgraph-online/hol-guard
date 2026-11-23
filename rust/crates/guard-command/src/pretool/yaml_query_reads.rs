//! One bounded `yq` read.
//!
//! `yq '.version' chart.yaml` is how a session reads a field out of a YAML,
//! JSON or TOML document, the way `jq` reads one out of JSON. The expression
//! is a program over the value read, the files are ordinary reads, and the
//! output goes to standard output: nothing is opened that the caller did not
//! name and nothing is written.
//!
//! Two things separate `yq` from `jq`, and both are handled here rather than
//! by widening the jq screen.
//!
//! `yq -i` rewrites the first file it is given, and `yq -s` writes one file
//! per result. Those are writes, so neither option is on the list below, and
//! an option the list does not name refuses the whole line rather than being
//! skipped. `--from-file` and `--split-exp-file` read the expression out of a
//! file and `--expression` moves it off the operand list, so each of them
//! would leave the screened expression unread; they are absent for that
//! reason. `-f` is not `--from-file` here -- in yq it is `--front-matter` and
//! takes `extract` or `process` -- so it is refused too rather than guessed
//! at.
//!
//! The expression goes through the same grammar `jq` filters go through.
//! yq's own operators for reaching outside the document -- `load`, `env`,
//! `strenv`, `eval` -- are not among the builtins that grammar admits, so an
//! expression naming one keeps its review. An expression that only assigns
//! (`.a = "b"`) prints the changed document and leaves the file alone, but it
//! still has to clear the grammar like any other.

use super::safe_reads::{command_read_target, jq_filter};

/// Flags that shape the output or the parse and carry no value.
const SWITCHES: &[&str] = &[
    "--colors",
    "--exit-status",
    "--header-preprocess",
    "--no-colors",
    "--no-doc",
    "--null-input",
    "--nul-output",
    "--prettyPrint",
    "--properties-array-brackets",
    "--security-disable-env-ops",
    "--security-disable-file-ops",
    "--string-interpolation",
    "--unwrapScalar",
    "--verbose",
    "--yaml-compact-seq-indent",
];

/// The short spellings of those flags. yq accepts them clustered, as in
/// `yq -Pr`, so each letter of a cluster is checked against this set.
const SWITCH_LETTERS: &str = "CeMNnPrvc0";

/// The formats `-p` and `-o` name, as yq's own help lists them.
const FORMATS: &[&str] = &[
    "auto", "a", "yaml", "y", "kyaml", "ky", "json", "j", "props", "p", "csv", "c", "tsv", "t",
    "xml", "x", "base64", "uri", "toml", "hcl", "h", "lua", "l", "ini", "i", "shell", "s",
];

/// The subcommands that evaluate an expression. `eval` is the default, so a
/// script may spell it either way.
const EVALUATORS: &[&str] = &["eval", "e", "eval-all", "ea"];

/// Whether `word` is one of the value-free flags.
fn switch(word: &str) -> bool {
    match word.strip_prefix('-') {
        Some(cluster) if !cluster.starts_with('-') => {
            !cluster.is_empty() && cluster.chars().all(|flag| SWITCH_LETTERS.contains(flag))
        }
        _ => SWITCHES.contains(&word),
    }
}

/// Whether `value` is an indent level: one or two digits.
fn indent(value: &str) -> bool {
    (1..=2).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `option` takes `value`, for the two options that name a format
/// and the one that names an indent level.
fn valued(option: &str, value: &str) -> bool {
    match option {
        "-p" | "--input-format" | "-o" | "--output-format" => FORMATS.contains(&value),
        "-I" | "--indent" => indent(value),
        _ => false,
    }
}

/// One yq run as its argument list spells it: an optional evaluating
/// subcommand, the options, the expression, and the files read after it.
struct Call<'a> {
    expression: usize,
    files: Vec<&'a str>,
    null_input: bool,
}

fn call(arguments: &[String]) -> Option<Call<'_>> {
    let mut expression = None;
    let mut files = Vec::new();
    let mut null_input = false;
    let mut subcommand_allowed = true;
    let mut index = 0;
    while let Some(word) = arguments.get(index).map(String::as_str) {
        if switch(word) {
            null_input |= word == "--null-input" || (!word.starts_with("--") && word.contains('n'));
            subcommand_allowed = false;
            index += 1;
            continue;
        }
        if let Some((option, value)) = word.split_once('=') {
            if option.starts_with("--") && valued(option, value) {
                subcommand_allowed = false;
                index += 1;
                continue;
            }
        }
        if let Some(value) = arguments.get(index + 1) {
            if valued(word, value) {
                subcommand_allowed = false;
                index += 2;
                continue;
            }
        }
        if word.starts_with('-') {
            return None;
        }
        if subcommand_allowed && expression.is_none() && EVALUATORS.contains(&word) {
            subcommand_allowed = false;
            index += 1;
            continue;
        }
        subcommand_allowed = false;
        if expression.is_none() {
            expression = Some(index);
        } else {
            files.push(word);
        }
        index += 1;
    }
    Some(Call {
        expression: expression?,
        files,
        null_input,
    })
}

impl Call<'_> {
    fn expression_safe(&self, arguments: &[String], context: super::PathContext<'_>) -> bool {
        let expression = &arguments[self.expression];
        !reinterpreted_as_a_file(expression, context)
            && jq_filter::safe_filter_binding(expression, &[])
    }

    fn files_readable(&self, context: super::PathContext<'_>) -> bool {
        self.files
            .iter()
            .all(|file| command_read_target(file, context, false))
    }
}

/// Whether `yq` would read its first word as a file rather than as the
/// expression. It decides that at run time: a first operand naming an
/// existing file ending in `.yq` is loaded as the program to run, and one
/// naming any other existing file is read as a document. A field name is a
/// legal file name, so `yq .env chart.yaml` prints the dotfile wherever one
/// is there, and a repository that carries a `.yq` file runs whatever it
/// holds, past every screen this module applies to the words themselves.
/// Both keep their review.
fn reinterpreted_as_a_file(expression: &str, context: super::PathContext<'_>) -> bool {
    if expression.ends_with(".yq") {
        return true;
    }
    let candidate = std::path::Path::new(expression);
    let resolved = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        let Some(cwd) = context.cwd else {
            // Without a working directory nothing here can say which names
            // are there. The piped form and `yq -n` name no file, so neither
            // carries a path proof that would catch the reinterpretation;
            // treat every relative first word as a file that may be there.
            return true;
        };
        std::path::Path::new(cwd).join(candidate)
    };
    resolved.exists()
}

/// `yq <expression> <file>...` reads the files it names, one after another.
/// `yq -n <expression>` reads no input at all.
/// Where the expression sits in `arguments`, when the call is a reading. The
/// expression selects fields inside the document, so its words are not names
/// on this machine and the sensitive-text screen skips them, exactly as it
/// skips a `jq` filter.
pub(in crate::pretool) fn expression_position(arguments: &[String]) -> Option<usize> {
    call(arguments).map(|call| call.expression)
}

pub(in crate::pretool) fn safe_yaml_query_file_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let Some(call) = call(arguments) else {
        return false;
    };
    let input = !call.files.is_empty() || call.null_input;
    input && call.files_readable(context) && call.expression_safe(arguments, context)
}

/// `... | yq <expression>` reads the document the pipeline already produced,
/// so it names no file of its own. It still takes the session's directory,
/// because `yq` reads its first word as a file wherever one of that name is
/// there, whatever the pipeline already handed it.
pub(in crate::pretool) fn safe_yaml_query_piped_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    call(arguments)
        .is_some_and(|call| call.files.is_empty() && call.expression_safe(arguments, context))
}

#[cfg(test)]
#[path = "yaml_query_reads_tests.rs"]
mod tests;
