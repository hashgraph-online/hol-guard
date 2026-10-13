//! Search text in Git reads.
//!
//! A `git grep` pattern and a `git log` pickaxe (`-S`, `-G`) or `--grep`
//! value are matched against repository content. Git never expands or runs
//! them, so an environment idiom such as `process.env` inside one is search
//! text, not an environment read. The sensitive-text screen applies to the
//! remaining arguments, the way plain `grep` and `rg` searches are judged on
//! their targets. A `git grep` outside the read-only grammar (pattern files,
//! pager helpers, unknown options) and a pattern that expands a variable or
//! substitution keep the whole-text screen.

use super::PathContext;

/// The segment arguments with search text left out, when the segment is a
/// `git grep` inside the read-only grammar or a `git log` naming search text.
pub(super) fn arguments_outside_search_text<'a>(
    arguments: &'a [String],
    context: PathContext<'_>,
) -> Option<Vec<&'a str>> {
    let search = search_positions(arguments, context)?;
    Some(
        arguments
            .iter()
            .enumerate()
            .filter(|(index, _)| !search.contains(index))
            .map(|(_, argument)| argument.as_str())
            .collect(),
    )
}

/// Whether the command touches sensitive text outside Git search literals.
/// Search text is set aside only for an exact parse without wrappers or
/// here-documents; anything else keeps the whole-text screen.
pub(super) fn sensitive_outside_search_text(
    model: &crate::CanonicalCommandV1,
    context: PathContext<'_>,
) -> bool {
    let normalized = model.normalized_text.as_str();
    if !super::sensitive_command(normalized) {
        return false;
    }
    if model.confidence != "exact"
        || !model.wrapper_chain.is_empty()
        || normalized.contains("<<")
        || model.segments.is_empty()
    {
        return true;
    }
    let screened: Vec<Option<String>> = model
        .segments
        .iter()
        .map(|segment| screened_text(segment, context))
        .collect();
    if screened.iter().all(Option::is_none) {
        return true;
    }
    model
        .segments
        .iter()
        .zip(&screened)
        .any(|(segment, text)| super::sensitive_command(text.as_deref().unwrap_or(&segment.text)))
}

/// The segment text with Git search literals left out, when it has any.
pub(super) fn screened_text(
    segment: &crate::CommandSegmentV1,
    context: PathContext<'_>,
) -> Option<String> {
    let executable = segment.executable.as_deref()?;
    if super::executable_basename(executable) != "git" {
        return None;
    }
    let screened = arguments_outside_search_text(&segment.arguments, context)?;
    Some(format!("{executable} {}", screened.join(" ")))
}

/// The positions in `arguments` of literal search text: `git grep` patterns
/// inside the read-only grammar, or `git log` pickaxe and `--grep` values.
pub(super) fn search_positions(
    arguments: &[String],
    context: PathContext<'_>,
) -> Option<Vec<usize>> {
    let inspected = crate::command_compatibility::git_inspection_arguments(arguments, context)?;
    let offset = arguments.len() - inspected.len() + 1;
    let (subcommand, rest) = inspected.split_first()?;
    let search = match subcommand.as_str() {
        "grep" => super::git_grep::pattern_indices(rest)?,
        "log" => log_search_indices(rest),
        _ => return None,
    };
    // A pattern that expands a variable or runs a substitution is not a
    // literal: it keeps the whole-text screen.
    if search.is_empty()
        || search
            .iter()
            .any(|position| rest[*position].contains(['$', '`']))
    {
        return None;
    }
    Some(
        search
            .into_iter()
            .map(|position| position + offset)
            .collect(),
    )
}

/// The positions of `-S`, `-G` and `--grep` values among `git log` options.
fn log_search_indices(arguments: &[String]) -> Vec<usize> {
    // Separate-value log options can consume a later -S, -G or --grep
    // token as ordinary option data. Conservatively preserve full sensitive
    // path screening whenever such an option occurs.
    const SEPARATE_VALUE: &[&str] = &[
        "--author", "--committer", "--since", "--after", "--until",
        "--before", "--skip", "--max-count", "-n", "--grep-reflog",
        "--min-parents", "--max-parents", "--pretty", "--format",
        "--date", "--encoding", "--decorate-refs",
        "--decorate-refs-exclude", "--line-prefix",
    ];
    let mut indices = Vec::new();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            break;
        }
        if SEPARATE_VALUE.contains(&argument.as_str()) {
            return Vec::new();
        }
        if matches!(argument.as_str(), "-S" | "-G" | "--grep") {
            if arguments.get(index + 1).is_some() {
                indices.push(index + 1);
            }
            index += 2;
            continue;
        }
        let attached =
            argument.len() > 2 && (argument.starts_with("-S") || argument.starts_with("-G"));
        if attached || argument.starts_with("--grep=") {
            indices.push(index);
        }
        index += 1;
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::log_search_indices;

    fn indices(command: &str) -> Vec<usize> {
        let arguments: Vec<String> = command.split(' ').map(str::to_owned).collect();
        log_search_indices(&arguments)
    }

    #[test]
    fn pickaxe_and_grep_values_are_search_text() {
        assert_eq!(indices("--oneline -S process.env.X -- src"), vec![2]);
        assert_eq!(indices("-Gprocess.env --oneline"), vec![0]);
        assert_eq!(indices("--grep=process.env -n 3"), vec![0]);
        assert_eq!(indices("--grep process.env HEAD"), vec![1]);
    }

    #[test]
    fn other_log_arguments_are_not_search_text() {
        assert!(indices("--oneline -- .env").is_empty());
        assert!(indices("-- -S .env").is_empty());
        assert!(indices("--author -S .env").is_empty());
        assert!(indices("--committer -G .env").is_empty());
        assert!(indices("--since --grep .env").is_empty());
        assert!(indices("-n -S .env").is_empty());
        assert!(indices("--pretty -G .env").is_empty());
        assert!(indices("--format --grep .env").is_empty());
        assert!(indices("--stat HEAD").is_empty());
        assert!(indices("-S").is_empty());
    }
}
