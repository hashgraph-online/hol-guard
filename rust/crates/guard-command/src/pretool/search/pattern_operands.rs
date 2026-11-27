//! Which `grep` or `rg` arguments are the search pattern rather than a path.
//!
//! The pattern is text the search looks for, not a file it opens. A pattern
//! such as `scan_secret_text` names no credential location, so screens that
//! look for credential paths among a command's words can leave it out.

use super::options;

/// The arguments of a `grep`, `egrep`, `fgrep` or `rg` argument list that
/// supply its pattern: every `-e`/`--regexp` argument or, without one, the
/// first positional. An attached pattern, as in `-neword` or
/// `--regexp=word`, is the whole argument that carries it.
///
/// Returns `None` when any option is one this reading does not know, so a
/// value-taking option can never shift a path into the pattern slot, and for
/// `rg --files`, which searches for no pattern and reads every positional as
/// a path.
pub(crate) fn search_pattern_words(executable: &str, arguments: &[String]) -> Option<Vec<String>> {
    let rg = match executable {
        "rg" => true,
        "grep" | "egrep" | "fgrep" => false,
        _ => return None,
    };
    let short_values: &[char] = if rg {
        &[
            'A', 'B', 'C', 'E', 'M', 'd', 'e', 'f', 'g', 'j', 'm', 'r', 't', 'T',
        ]
    } else {
        &['A', 'B', 'C', 'D', 'X', 'd', 'e', 'f', 'm']
    };
    let mut option_patterns = Vec::new();
    let mut pattern_option = false;
    let mut positionals = Vec::new();
    let mut options_enabled = true;
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        index += 1;
        if !options_enabled || argument == "-" || !argument.starts_with('-') {
            positionals.push(argument.clone());
            continue;
        }
        if argument == "--" {
            options_enabled = false;
            continue;
        }
        if rg && argument == "--files" {
            return None;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((name, value)) => (format!("--{name}"), Some(value)),
                None => (argument.clone(), None),
            };
            let role = if rg {
                options::rg_value_role(&name)
            } else {
                options::grep_value_role(&name)
            };
            match role {
                // grep's colour option takes only an attached `=WHEN`, so
                // a bare `--color` leaves the next word where it was.
                Some(_)
                    if !rg
                        && attached.is_none()
                        && matches!(name.as_str(), "--color" | "--colour") => {}
                Some(role) => {
                    let value = match attached {
                        Some(_) => argument.clone(),
                        None => {
                            index += 1;
                            arguments.get(index - 1)?.clone()
                        }
                    };
                    if name == "--regexp" {
                        option_patterns.push(value);
                    }
                    pattern_option |=
                        matches!(role, super::SearchValueRole::Pattern) || name == "--file";
                }
                None if attached.is_none() && known_flag(rg, &name) => {}
                None => return None,
            }
            continue;
        }
        for (offset, option) in argument[1..].char_indices() {
            if !short_values.contains(&option) {
                continue;
            }
            let attached = &argument[1 + offset + option.len_utf8()..];
            let value = if attached.is_empty() {
                index += 1;
                arguments.get(index - 1)?.clone()
            } else {
                argument.clone()
            };
            if option == 'e' {
                option_patterns.push(value);
            }
            pattern_option |= matches!(option, 'e' | 'f');
            break;
        }
    }
    if pattern_option {
        return Some(option_patterns);
    }
    Some(positionals.into_iter().take(1).collect())
}

fn known_flag(rg: bool, name: &str) -> bool {
    if rg {
        return options::safe_rg_flag(name)
            || matches!(name, "--hidden" | "--no-ignore" | "--follow");
    }
    options::safe_grep_flag(name)
        || matches!(
            name,
            "--recursive"
                | "--dereference-recursive"
                | "--files-with-matches"
                | "--files-without-match"
                | "--basic-regexp"
                | "--no-ignore-case"
        )
}

#[cfg(test)]
mod tests {
    use super::search_pattern_words;

    fn words(executable: &str, line: &str) -> Option<Vec<String>> {
        let arguments: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        search_pattern_words(executable, &arguments)
    }

    #[test]
    fn the_first_positional_is_the_pattern_without_an_option_pattern() {
        assert_eq!(
            words("grep", "-rln scan_secret_text src"),
            Some(vec!["scan_secret_text".into()])
        );
        assert_eq!(
            words("rg", "-n secret_value src"),
            Some(vec!["secret_value".into()])
        );
        assert_eq!(
            words("grep", "-n -A 2 token_budget README.md"),
            Some(vec!["token_budget".into()])
        );
        assert_eq!(words("grep", "-- -token x"), Some(vec!["-token".into()]));
    }

    #[test]
    fn an_option_pattern_turns_every_positional_into_a_path() {
        assert_eq!(
            words("grep", "-rn -e api_token -e x src"),
            Some(vec!["api_token".into(), "x".into()])
        );
        assert_eq!(
            words("grep", "-rnepassword .env"),
            Some(vec!["-rnepassword".into()])
        );
        assert_eq!(
            words("rg", "--regexp=api_token .env"),
            Some(vec!["--regexp=api_token".into()])
        );
        assert_eq!(words("grep", "-f patterns.txt .env"), Some(vec![]));
    }

    #[test]
    fn an_unknown_option_or_program_reads_no_pattern() {
        assert_eq!(words("grep", "--frobnicate .env x"), None);
        assert_eq!(words("rg", "--pre=cat x .env"), None);
        assert_eq!(words("cat", "x .env"), None);
        assert_eq!(words("grep", "-A"), None);
        assert_eq!(words("rg", "--files .env"), None);
    }

    #[test]
    fn a_bare_grep_colour_option_takes_no_value() {
        assert_eq!(words("grep", "--color x .env"), Some(vec!["x".into()]));
        assert_eq!(words("grep", "--colour x .env"), Some(vec!["x".into()]));
        assert_eq!(
            words("grep", "--color=always x .env"),
            Some(vec!["x".into()])
        );
        assert_eq!(words("rg", "--color never x .env"), Some(vec!["x".into()]));
    }
}
