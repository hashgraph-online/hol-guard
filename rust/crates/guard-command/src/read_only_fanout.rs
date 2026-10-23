//! Syntax of read-only `find` fan-out: `find ... -exec CHILD {} +` and
//! `find ... -print0 | xargs -0 CHILD`.
//!
//! The parser used to mark every `xargs` and `find -exec` command uncertain,
//! which stopped ordinary agent reads such as `find src -name '*.ts' -exec cat
//! {} +`. This module only recognizes the shape: a `find` expression of name,
//! type and depth tests, optionally skipping a vendored tree with the
//! `-name DIR -prune -o` idiom, whose result is handed to one child from a
//! short read-only list. It decides nothing about safety. The pre-tool proof
//! (`pretool::fanout_reads`) still requires verified workspace-contained
//! roots, regular files only (`-type f`, so a workspace symlink is never
//! followed), and the existing read-only proof of the child. Everything else,
//! including `-I` substitution, `sh -c`, `-delete`, `-fprint`, `-ok` and
//! every other producer, keeps the uncertain model.
//!
//! One more producer is recognized: `git merge-base REV... | xargs git ...`,
//! which agents use to inspect the commit two branches share. `merge-base`
//! prints only object names, so the child receives hexadecimal words, and the
//! pre-tool proof still requires the child's own Git read proof.

use crate::parser_executables::executable_basename;
use crate::CommandSegmentV1;

/// Placeholder operand the child proof stands in for the unknown file names.
pub(crate) const PLACEHOLDER: &str = "guard-fanout-result";

/// Object name the Git child proof stands in for the `merge-base` result.
pub(crate) const OBJECT_NAME_PLACEHOLDER: &str = "0123456789abcdef0123456789abcdef01234567";

/// Children worth proving at all. Each still has to pass its own read-only
/// proof with the file operand appended; this list adds no admission.
const CHILDREN: [&str; 9] = [
    "cat", "head", "tail", "wc", "grep", "rg", "ls", "stat", "od",
];

/// Children that print counts or metadata, never file contents.
const METADATA_CHILDREN: [&str; 3] = ["wc", "ls", "stat"];

const MAX_ROOTS: usize = 8;
const MAX_PATTERN_BYTES: usize = 256;
const MAX_DEPTH: u8 = 32;

pub(crate) struct FindShape<'a> {
    pub roots: &'a [String],
    pub regular_files_only: bool,
    pub patterns: Vec<&'a str>,
    pub print0: bool,
}

pub(crate) struct FindExec<'a> {
    pub shape: FindShape<'a>,
    pub child: &'a [String],
}

pub(crate) struct Xargs<'a> {
    pub null_separated: bool,
    pub no_run_if_empty: bool,
    pub child: &'a [String],
}

/// Trailing `2>&1` only merges the segment's own stderr.
fn without_stderr_merge(arguments: &[String]) -> &[String] {
    let mut end = arguments.len();
    while end > 0 && arguments[end - 1] == "2>&1" {
        end -= 1;
    }
    &arguments[..end]
}

/// Whether the child reads file contents (and so needs a bounded name test).
pub(crate) fn child_reads_contents(child: &[String]) -> bool {
    child
        .first()
        .is_some_and(|name| !METADATA_CHILDREN.contains(&executable_basename(name)))
}

fn child_listed(child: &[String]) -> bool {
    child.first().is_some_and(|name| {
        !name.contains(['/', '\\']) && CHILDREN.contains(&executable_basename(name))
    })
}

/// Whether the child stays bounded when xargs runs it with no file operand,
/// as it does on empty input without `-r`. The readers then read the empty
/// input and `ls`/`stat` print metadata only, but `rg` and a recursive `grep`
/// search the whole working directory. A short option holding `r`, `R` or
/// `d` counts as recursive.
pub(crate) fn bounded_without_operands(child: &[String]) -> bool {
    let Some((name, rest)) = child.split_first() else {
        return false;
    };
    match executable_basename(name) {
        "cat" | "head" | "tail" | "wc" | "od" | "ls" | "stat" => true,
        "grep" => !rest.iter().any(|argument| {
            argument.starts_with("--recursive")
                || argument.starts_with("--dereference-recursive")
                || argument.starts_with("--directories")
                || (argument.starts_with('-')
                    && !argument.starts_with("--")
                    && argument.contains(['r', 'R', 'd']))
        }),
        _ => false,
    }
}

/// Flat `find` operands: roots, an optional `-prune` prefix, then a
/// conjunction of name, type and depth tests. An operator in the printing
/// branch (`-o`, parentheses), `-L`, `-H`, `-follow` and every action other
/// than `-print`/`-print0` are not part of the shape.
pub(crate) fn find_shape(arguments: &[String]) -> Option<FindShape<'_>> {
    let end = arguments
        .iter()
        .position(|argument| argument.starts_with('-') || matches!(argument.as_str(), "!" | "("))
        .unwrap_or(arguments.len());
    let (roots, expression) = arguments.split_at(end);
    if roots.is_empty() || roots.len() > MAX_ROOTS {
        return None;
    }
    let mut shape = FindShape {
        roots,
        regular_files_only: false,
        patterns: Vec::new(),
        print0: false,
    };
    let mut index = 0;
    // `find src -name node_modules -prune -o REST` is how an agent skips a
    // vendored tree. A pruned branch only takes directories out of the walk,
    // so it never widens what REST hands the child, and its own patterns are
    // not part of the bound REST has to carry.
    while let Some(after) = pruned_branch(expression, index) {
        index = after;
    }
    while index < expression.len() {
        if shape.print0 {
            return None;
        }
        let mut token = expression[index].as_str();
        index += 1;
        let negated = matches!(token, "!" | "-not");
        if negated {
            token = expression.get(index)?.as_str();
            index += 1;
        }
        match token {
            "-print" | "-a" | "-and" if !negated => {}
            "-print0" if !negated => shape.print0 = true,
            "-name" | "-iname" | "-path" | "-ipath" => {
                let pattern = expression.get(index)?;
                if !bounded_test_pattern(pattern) {
                    return None;
                }
                // A negated test only takes names away, so it is never the
                // bound a content-reading child is admitted under.
                if !negated && matches!(token, "-name" | "-iname") {
                    shape.patterns.push(pattern);
                }
                index += 1;
            }
            "-type" if !negated => {
                if expression.get(index).map(String::as_str) != Some("f") {
                    return None;
                }
                shape.regular_files_only = true;
                index += 1;
            }
            "-maxdepth" | "-mindepth" if !negated => {
                if !bounded_depth(expression.get(index)?) {
                    return None;
                }
                index += 1;
            }
            _ => return None,
        }
    }
    Some(shape)
}

fn bounded_test_pattern(pattern: &str) -> bool {
    pattern.len() <= MAX_PATTERN_BYTES && !pattern.contains(['\n', '\r', '\0'])
}

fn bounded_depth(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u8>().is_ok_and(|count| count <= MAX_DEPTH)
}

/// A `TESTS -prune -o` branch at `index`, answering where the expression after
/// it resumes. `find` evaluates `-prune` to true and `-o` short-circuits on
/// it, so an entry the branch matches is dropped from the walk rather than
/// handed to the child.
fn pruned_branch(expression: &[String], index: usize) -> Option<usize> {
    let index = branch_tests(expression, index)?;
    if expression.get(index).map(String::as_str) != Some("-prune") {
        return None;
    }
    if !matches!(
        expression.get(index + 1).map(String::as_str),
        Some("-o" | "-or")
    ) {
        return None;
    }
    Some(index + 2)
}

/// The tests a pruned branch names directories with: name and path tests and
/// `-type d`. `-o` joins them only inside parentheses, where it cannot reach
/// past the branch; an unparenthesized `-o` would make the whole expression a
/// disjunction and is left to the uncertain model.
fn branch_tests(expression: &[String], index: usize) -> Option<usize> {
    let parenthesized = expression.get(index).map(String::as_str) == Some("(");
    let mut index = index + usize::from(parenthesized);
    let mut tests = 0_usize;
    loop {
        match expression.get(index).map(String::as_str) {
            Some("-a" | "-and") if tests > 0 => index += 1,
            Some("-o" | "-or") if parenthesized && tests > 0 => index += 1,
            Some("-name" | "-iname" | "-path" | "-ipath") => {
                if !bounded_test_pattern(expression.get(index + 1)?) {
                    return None;
                }
                index += 2;
                tests += 1;
            }
            Some("-type") => {
                if expression.get(index + 1).map(String::as_str) != Some("d") {
                    return None;
                }
                index += 2;
                tests += 1;
            }
            _ => break,
        }
    }
    if tests == 0 {
        return None;
    }
    if parenthesized {
        if expression.get(index).map(String::as_str) != Some(")") {
            return None;
        }
        index += 1;
    }
    Some(index)
}

/// `find SHAPE -exec CHILD {} +` or `... {} \;`, with the file operand last.
pub(crate) fn find_exec(arguments: &[String]) -> Option<FindExec<'_>> {
    let arguments = without_stderr_merge(arguments);
    let at = arguments.iter().position(|argument| argument == "-exec")?;
    let shape = find_shape(&arguments[..at])?;
    if shape.print0 {
        return None;
    }
    let (terminator, body) = arguments[at + 1..].split_last()?;
    if !matches!(terminator.as_str(), "+" | ";") {
        return None;
    }
    let (marker, child) = body.split_last()?;
    // find ends an `-exec` body at its first `;` (or a `+` right after `{}`)
    // and parses what follows as more expression, such as `-o -delete`. A
    // child holding either token would hide that expression from the proof.
    if marker != "{}"
        || child
            .iter()
            .any(|argument| argument.contains("{}") || matches!(argument.as_str(), ";" | "+"))
    {
        return None;
    }
    child_listed(child).then_some(FindExec { shape, child })
}

fn bounded_count(value: &str) -> bool {
    !value.is_empty() && value.len() <= 3 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// `xargs [-0] [-r] [-n N] [-P N] CHILD ARGS`: no replacement string, no
/// prompt, no input file or delimiter options.
fn xargs_options(arguments: &[String]) -> Option<Xargs<'_>> {
    let arguments = without_stderr_merge(arguments);
    let mut null_separated = false;
    let mut no_run_if_empty = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index).map(String::as_str) {
        if !argument.starts_with('-') {
            break;
        }
        index += 1;
        match argument {
            "-0" | "--null" => null_separated = true,
            "-r" | "--no-run-if-empty" => no_run_if_empty = true,
            "-n" | "-P" | "--max-args" | "--max-procs" => {
                if !bounded_count(arguments.get(index)?) {
                    return None;
                }
                index += 1;
            }
            _ => {
                let value = argument
                    .strip_prefix("--max-args=")
                    .or_else(|| argument.strip_prefix("--max-procs="))
                    .or_else(|| argument.strip_prefix("-n"))
                    .or_else(|| argument.strip_prefix("-P"))?;
                if !bounded_count(value) {
                    return None;
                }
            }
        }
    }
    Some(Xargs {
        null_separated,
        no_run_if_empty,
        child: &arguments[index..],
    })
}

/// `xargs [-0] [-r] [-n N] [-P N] CHILD ARGS` with a child from the read-only list.
pub(crate) fn xargs(arguments: &[String]) -> Option<Xargs<'_>> {
    xargs_options(arguments).filter(|xargs| child_listed(xargs.child))
}

/// `xargs [-r] [-n N] [-P N] git ARGS`: a plain `git` child that receives the
/// object names `git merge-base` printed.
pub(crate) fn xargs_git(arguments: &[String]) -> Option<Xargs<'_>> {
    xargs_options(arguments).filter(|xargs| {
        !xargs.null_separated && xargs.child.first().is_some_and(|name| name == "git")
    })
}

/// `git merge-base REV...` with only literal revisions prints object names and
/// nothing else, so the words `xargs` appends are hexadecimal.
pub(crate) fn object_name_producer(segment: &CommandSegmentV1) -> bool {
    segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && segment.executable.as_deref() == Some("git")
        && matches!(without_stderr_merge(&segment.arguments), [subcommand, revisions @ ..]
        if subcommand == "merge-base"
            && !revisions.is_empty()
            && revisions.iter().all(|revision| {
                !revision.starts_with('-')
                    && !revision.is_empty()
                    && revision.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || b"/._-~^@{}".contains(&byte)
                    })
            }))
}

/// A `git` child of `xargs` fed directly by `git merge-base` in the same pipeline.
pub(crate) fn xargs_follows_object_names(
    previous: &CommandSegmentV1,
    pipeline_index: usize,
    execution_context: &str,
    arguments: &[String],
) -> bool {
    previous.pipeline_index + 1 == pipeline_index
        && previous.execution_context == execution_context
        && object_name_producer(previous)
        && xargs_git(arguments).is_some()
}

/// A `xargs` segment fed directly by a `find` segment of the same pipeline.
pub(crate) fn xargs_follows_find(
    previous: &CommandSegmentV1,
    pipeline_index: usize,
    execution_context: &str,
    arguments: &[String],
) -> bool {
    previous.pipeline_index + 1 == pipeline_index
        && previous.execution_context == execution_context
        && previous.environment_names.is_empty()
        && previous.wrapper_chain.is_empty()
        && !previous.path_overridden
        && previous
            .executable
            .as_deref()
            .is_some_and(|name| executable_basename(name) == "find")
        && find_shape(&previous.arguments).is_some()
        && xargs(arguments).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn find_exec_accepts_flat_read_only_shape() {
        let a = args(&[
            "src", "-type", "f", "-name", "*.ts", "-exec", "cat", "{}", "+",
        ]);
        let parsed = find_exec(&a).unwrap();
        assert!(parsed.shape.regular_files_only);
        assert_eq!(parsed.child, &a[6..7]);
        assert!(find_exec(&args(&["src", "-exec", "grep", "-n", "x", "{}", ";"])).is_some());
    }

    #[test]
    fn find_exec_rejects_actions_children_and_operators() {
        for case in [
            &["src", "-exec", "rm", "{}", "+"][..],
            &["src", "-exec", "sh", "-c", "cat {}", "+"],
            &["src", "-exec", "cat", "{}", "+", "-delete"],
            &["src", "-execdir", "cat", "{}", "+"],
            &["src", "-ok", "cat", "{}", ";"],
            &[
                "src", "-name", "a", "-o", "-name", "b", "-exec", "cat", "{}", "+",
            ],
            &["src", "-fprint", "out", "-exec", "cat", "{}", "+"],
            &["src", "-exec", "/bin/cat", "{}", "+"],
            &["src", "-exec", "cat", "x{}", "+"],
            &[
                "src", "-exec", "grep", "-e", ";", "-o", "-delete", "-fprintf", "{}", ";",
            ],
            &["-L", "src", "-exec", "cat", "{}", "+"],
            &["-exec", "cat", "{}", "+"],
        ] {
            assert!(find_exec(&args(case)).is_none(), "{case:?}");
        }
    }

    #[test]
    fn xargs_accepts_safe_options_only() {
        assert!(xargs(&args(&["-0", "-r", "-n", "5", "-P4", "cat"])).is_some());
        assert!(
            xargs(&args(&["-0", "grep", "-n", "x"]))
                .unwrap()
                .null_separated
        );
        for case in [
            &["-I{}", "cat", "{}"][..],
            &["-I", "{}", "cat"],
            &["-i", "cat"],
            &["--replace", "cat"],
            &["-0", "sh", "-c", "cat"],
            &["-0", "rm"],
            &["-0"],
            &["-a", "list", "cat"],
            &["-n", "x", "cat"],
        ] {
            assert!(xargs(&args(case)).is_none(), "{case:?}");
        }
    }

    fn confidence(command: &str) -> String {
        crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap()
        .confidence
    }

    #[test]
    fn parser_models_only_the_read_only_shapes() {
        for command in [
            "find src -type f -exec cat {} +",
            "find src -type f -print0 | xargs -0 cat",
            "find src -type f | xargs grep -n x",
        ] {
            assert_eq!(confidence(command), "exact", "{command}");
        }
        for command in [
            "find src -type f | xargs -I{} sh -c 'cat {}'",
            "find src -type f -print0 | xargs -0 rm",
            "find src -type f -exec rm {} +",
            "find src -type f -delete -exec cat {} +",
            "echo a | xargs cat",
            "xargs cat",
            "find src -type f | sort | xargs cat",
        ] {
            assert_eq!(confidence(command), "uncertain", "{command}");
        }
    }
}
