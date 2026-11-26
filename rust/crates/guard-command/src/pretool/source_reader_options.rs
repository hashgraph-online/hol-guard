//! The operands of the plain readers the source-file read exemption accepts.
//!
//! Each reader's options are read against the few it has that only shape the
//! output: line and byte counts, numbering, and the counters `wc` prints. Any
//! other option, or a value that is not a plain count, leaves the segment
//! outside the exemption.

/// The file operands of `cat`, `head`, `tail`, `wc` or `nl`, or `None` when
/// an argument is an option this reading does not know.
pub(super) fn reader_operands<'a>(name: &str, arguments: &'a [String]) -> Option<Vec<&'a String>> {
    if !matches!(name, "cat" | "head" | "tail" | "wc" | "nl") {
        return None;
    }
    let mut operands = Vec::new();
    let mut options_ended = false;
    let mut values = arguments.iter();
    while let Some(argument) = values.next() {
        if options_ended || argument == "-" || !argument.starts_with('-') {
            operands.push(argument);
            continue;
        }
        if argument == "--" {
            options_ended = true;
            continue;
        }
        match name {
            "head" | "tail" => {
                if let Some(value) = argument
                    .strip_prefix("--lines=")
                    .or_else(|| argument.strip_prefix("--bytes="))
                {
                    count(value).then_some(())?;
                } else if matches!(argument.as_str(), "-n" | "-c" | "--lines" | "--bytes") {
                    count(values.next()?).then_some(())?;
                } else {
                    let rest = &argument[1..];
                    let value = rest
                        .strip_prefix('n')
                        .or_else(|| rest.strip_prefix('c'))
                        .unwrap_or(rest);
                    (count(value) || matches!(rest, "q" | "v")).then_some(())?;
                }
            }
            "wc" => {
                let known = matches!(
                    argument.as_str(),
                    "--lines" | "--bytes" | "--chars" | "--words" | "--max-line-length"
                ) || cluster(argument, "lcwmL");
                known.then_some(())?;
            }
            "cat" => cluster(argument, "nbsAeEtTuv").then_some(())?,
            // `nl -ba` and the like: short, numbering-only options.
            "nl" => (argument.len() <= 3
                && !argument[1..]
                    .contains(|c: char| c.is_alphabetic() && c != 'n' && c != 'b' && c != 'a'))
            .then_some(())?,
            _ => return None,
        }
    }
    Some(operands)
}

/// The file operands of `sed -n SCRIPT FILE...` when the script only prints
/// numbered lines or ranges, such as `1,40p` or `5p;$p`.
pub(super) fn sed_print_operands(arguments: &[String]) -> Option<Vec<&String>> {
    let (quiet, rest) = arguments.split_first()?;
    if !matches!(quiet.as_str(), "-n" | "--quiet" | "--silent") {
        return None;
    }
    let (script, operands) = rest.split_first()?;
    if !script.split(';').all(line_print) {
        return None;
    }
    operands
        .iter()
        .all(|operand| operand == "-" || !operand.starts_with('-'))
        .then(|| operands.iter().collect())
}

/// `N`, `$` or `N,M` followed by `p`.
fn line_print(command: &str) -> bool {
    let Some(range) = command.strip_suffix('p') else {
        return false;
    };
    let address =
        |part: &str| part == "$" || (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    match range.split_once(',') {
        Some((first, last)) => address(first) && address(last),
        None => address(range),
    }
}

/// A plain line or byte count, optionally signed: `20`, `+5`, `-3`.
fn count(value: &str) -> bool {
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// A short-option cluster made only of `letters`.
fn cluster(argument: &str, letters: &str) -> bool {
    let rest = &argument[1..];
    !rest.is_empty() && !rest.starts_with('-') && rest.chars().all(|c| letters.contains(c))
}

#[cfg(test)]
mod tests {
    use super::{reader_operands, sed_print_operands};

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    fn reads(name: &str, line: &str) -> Option<Vec<String>> {
        let arguments = args(line);
        let operands = if name == "sed" {
            sed_print_operands(&arguments)
        } else {
            reader_operands(name, &arguments)
        };
        operands.map(|found| found.into_iter().cloned().collect())
    }

    #[test]
    fn output_shaping_options_leave_only_the_files() {
        assert_eq!(reads("head", "-n 5 a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(reads("head", "-100 a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(reads("tail", "-n +20 a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(reads("head", "-c 100 a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(reads("head", "--lines=5 a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(
            reads("wc", "-l a.rs b.rs"),
            Some(vec!["a.rs".into(), "b.rs".into()])
        );
        assert_eq!(reads("cat", "-n a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(reads("nl", "-ba a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(reads("sed", "-n 1,40p a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(reads("sed", "-n 5p;$p a.rs"), Some(vec!["a.rs".into()]));
        assert_eq!(reads("sed", "-n 10,$p a.rs"), Some(vec!["a.rs".into()]));
    }

    #[test]
    fn any_other_option_or_script_is_not_a_plain_read() {
        assert_eq!(reads("head", "-n five a.rs"), None);
        assert_eq!(reads("tail", "-f a.rs"), None);
        assert_eq!(reads("wc", "--files0-from=list a.rs"), None);
        assert_eq!(reads("cat", "--show-all a.rs"), None);
        assert_eq!(reads("sed", "1,40p a.rs"), None);
        assert_eq!(reads("sed", "-n 1,40w out.rs a.rs"), None);
        assert_eq!(reads("sed", "-n 1e a.rs"), None);
        assert_eq!(reads("sed", "-n -i 1p a.rs"), None);
        assert_eq!(reads("sed", "-n 1p -i a.rs"), None);
        assert_eq!(reads("sort", "a.rs"), None);
        assert_eq!(reads("python3", "a.py"), None);
    }
}
