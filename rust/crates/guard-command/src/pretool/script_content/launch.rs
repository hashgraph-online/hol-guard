//! Which program an interpreter launch runs, and what feeds its standard
//! input.

use std::path::Path;

use super::{extension, Language, NODE_EXTENSIONS, NODE_VALUE_OPTIONS, PYTHON_VALUE_OPTIONS};
use crate::CommandSegmentV1;

/// `deno eval` options that take the next word as their value.
const DENO_EVAL_VALUE_OPTIONS: &[&str] = &[
    "--ext",
    "--import-map",
    "--config",
    "-c",
    "--location",
    "--seed",
    "--cert",
    "--lock",
    "-L",
    "--log-level",
];

/// The program an interpreter runs.
pub(super) enum Program<'a> {
    Script(&'a str),
    Inline(&'a str),
    Stdin,
}

/// What an interpreter reading its program from standard input is fed.
pub(super) enum Fed {
    Text(String),
    File(String),
}

/// The interpreter a segment launches and its program, and whether it runs
/// inside a container or pod rather than on this machine.
pub(super) fn launched_program(
    segment: &CommandSegmentV1,
) -> Option<(Language, Program<'_>, bool)> {
    let name = super::super::executable_basename(segment.executable.as_deref()?);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    let arguments = segment.arguments.as_slice();
    if matches!(name, "kubectl" | "oc") && arguments.first().is_some_and(|verb| verb == "exec") {
        let split = arguments.iter().position(|argument| argument == "--")?;
        let (interpreter, rest) = arguments[split + 1..].split_first()?;
        let (language, program) = interpreter_program(interpreter, rest)?;
        return Some((language, program, true));
    }
    let (language, program) = interpreter_program(name, arguments)?;
    Some((language, program, false))
}

fn interpreter_program<'a>(
    executable: &str,
    arguments: &'a [String],
) -> Option<(Language, Program<'a>)> {
    let name = super::super::executable_basename(executable);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    let python = name.strip_prefix("python").is_some_and(|version| {
        version
            .split('.')
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    if python {
        let program = program(arguments, PYTHON_VALUE_OPTIONS, &["-c"], &["-m"])?;
        return Some((Language::Python, program));
    }
    let arguments = match (name, arguments) {
        ("deno", [eval, rest @ ..]) if eval == "eval" => {
            let mut words = rest.iter();
            while let Some(word) = words.next() {
                if !word.starts_with('-') {
                    return Some((Language::Node, Program::Inline(word)));
                }
                if DENO_EVAL_VALUE_OPTIONS.contains(&word.as_str()) {
                    words.next();
                }
            }
            return None;
        }
        ("bun" | "deno", [run, rest @ ..]) if run == "run" => rest,
        ("node" | "nodejs" | "bun" | "tsx", rest) => rest,
        _ => return None,
    };
    let program = program(
        arguments,
        NODE_VALUE_OPTIONS,
        &["-e", "--eval", "-p", "--print"],
        &[],
    )?;
    match program {
        Program::Script(script)
            if !NODE_EXTENSIONS.contains(&extension(Path::new(script)).as_str()) =>
        {
            None
        }
        // Only Node reads a program from standard input; Bun, Deno and tsx
        // given none start something else.
        Program::Stdin if !matches!(name, "node" | "nodejs") => None,
        program => Some((Language::Node, program)),
    }
}

/// The program named by an interpreter's arguments: the first argument that
/// is not an option, inline source, or standard input (`-`, or no operand).
/// `None` when a module runs instead.
fn program<'a>(
    arguments: &'a [String],
    value_options: &[&str],
    inline: &[&str],
    module: &[&str],
) -> Option<Program<'a>> {
    let mut rest = arguments.iter();
    while let Some(argument) = rest.next() {
        let argument = argument.as_str();
        if inline.contains(&argument) {
            return rest.next().map(String::as_str).map(Program::Inline);
        }
        if let Some(source) = inline
            .iter()
            .filter(|flag| flag.starts_with("--"))
            .find_map(|flag| argument.strip_prefix(flag)?.strip_prefix('='))
        {
            return Some(Program::Inline(source));
        }
        if module.contains(&argument) {
            return None;
        }
        if argument == "-" {
            return Some(Program::Stdin);
        }
        if argument == "--" {
            return Some(
                rest.next()
                    .map(String::as_str)
                    .map_or(Program::Stdin, Program::Script),
            );
        }
        if value_options.contains(&argument) {
            rest.next()?;
            continue;
        }
        if !argument.starts_with('-') {
            return Some(Program::Script(argument));
        }
    }
    Some(Program::Stdin)
}

/// Heredocs and redirects of the command's top-level segments, by position.
pub(super) struct Stdin {
    heredocs: Vec<crate::shell_structure::ShellHeredoc>,
    redirects: Vec<crate::command_structure::CommandRedirect>,
}

impl Stdin {
    pub(super) fn new(text: &str) -> Self {
        let heredocs = crate::shell_structure::extract_heredocs(text);
        let masked = crate::shell_structure::mask_heredoc_bodies(text, &heredocs);
        let redirects = crate::command_structure::extract_command_redirects(&masked, &heredocs);
        Self {
            heredocs,
            redirects,
        }
    }

    /// What segment `index` reads on standard input, when exactly one source
    /// feeds it.
    pub(super) fn source(&self, segments: &[CommandSegmentV1], index: usize) -> Option<Fed> {
        let segment = &segments[index];
        if !segment.execution_context.starts_with("top") {
            return None;
        }
        let owns = |at: usize| segment.span.start <= at && at <= segment.span.end;
        let mut fed = Vec::new();
        fed.extend(
            self.heredocs
                .iter()
                .filter(|heredoc| owns(heredoc.operator_start))
                .map(|heredoc| Fed::Text(heredoc.body.clone())),
        );
        // Any input redirect the scan cannot read leaves the source unknown,
        // since the last one wins.
        for redirect in self
            .redirects
            .iter()
            .filter(|redirect| owns(redirect.start))
        {
            match redirect.operator.as_str() {
                "<" | "0<" => fed.push(Fed::File(plain_path(&redirect.target)?)),
                "<<<" | "0<<<" | "<&" | "0<&" | "<>" | "0<>" => return None,
                _ => {}
            }
        }
        if segment.pipeline_index > 0 {
            let feeder = segments.iter().find(|prior| {
                prior.execution_context == segment.execution_context
                    && prior.pipeline_index + 1 == segment.pipeline_index
            })?;
            let is_cat = feeder
                .executable
                .as_deref()
                .is_some_and(|value| super::super::executable_basename(value) == "cat");
            match feeder.arguments.as_slice() {
                [file] if is_cat => fed.push(Fed::File(plain_path(file)?)),
                [separator, file] if is_cat && separator == "--" => {
                    fed.push(Fed::File(plain_path(file)?))
                }
                _ => return None,
            }
        }
        match <[Fed; 1]>::try_from(fed) {
            Ok([only]) => Some(only),
            Err(_) => None,
        }
    }
}

/// A redirect or `cat` operand that names one file as written.
fn plain_path(target: &str) -> Option<String> {
    (!target.is_empty()
        && !target.starts_with('-')
        && !target.contains(['$', '`', '"', '\'', '\\', '*', '?', '[', '{', '~']))
    .then(|| target.to_owned())
}
