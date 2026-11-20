//! The `env` controls that only decide which names the program starts with.
//!
//! `env -u NODE_OPTIONS npm test` runs the test suite `npm test` runs, so the
//! prefix leaves the program this text names untouched and the names it
//! decided join `environment_names`. Every other option leaves `env` as the
//! executable: `-i` clears the environment, which takes the search path the
//! program is resolved against with it, `-C` runs the program in another
//! directory, and `-S` carries a whole command line inside the option's own
//! value. None of those is the program this text names.

use crate::assignment_name;

/// The name this parser reads after `env -u`.
///
/// A real `unsetenv` refuses only an empty name or one holding `=`, so
/// `env -u NODE-OPTIONS npm test` does start the test suite. This reads the
/// narrower set on purpose: the token after `-u` is where a misread turns
/// `env -u -S '/bin/bash -c' 'rm -rf workspace/target'` into a program this
/// text does not name, and a plain environment variable name is the only
/// spelling where the following word is certainly the program. Anything else
/// keeps `env`'s own spelling and stays under review, which costs a review on
/// names no shell exports.
fn removable_name(token: &str) -> Option<&str> {
    let mut characters = token.chars();
    let first = characters.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    if !characters.all(|value| value == '_' || value.is_ascii_alphanumeric()) {
        return None;
    }
    Some(token)
}

/// Reads an `env` prefix from the word after `env` itself.
///
/// Returns where the program word sits and the names the prefix decided, or
/// `None` when `env` names no program at all and is itself the command to
/// judge. Assignments end option parsing for the shell as they do for `env`,
/// so a `-u` behind one is the program rather than a control.
pub(super) fn env_names(tokens: &[String], mut next: usize) -> Option<(usize, Vec<String>)> {
    let mut names = Vec::new();
    let mut controls = 0usize;
    loop {
        match tokens.get(next)?.as_str() {
            "-u" | "--unset" => {
                names.push(removable_name(tokens.get(next + 1)?)?.to_owned());
                controls += 1;
                next += 2;
                continue;
            }
            value if value.starts_with("--unset=") => {
                names.push(removable_name(&value["--unset=".len()..])?.to_owned());
            }
            value if value.len() > 2 && value.starts_with("-u") => {
                names.push(removable_name(&value[2..])?.to_owned());
            }
            "--" => {
                controls += 1;
                next += 1;
                break;
            }
            value if value.starts_with('-') => return None,
            _ => break,
        }
        controls += 1;
        next += 1;
    }
    while let Some(name) = tokens.get(next).and_then(|value| assignment_name(value)) {
        names.push(name.to_owned());
        next += 1;
    }
    if names.is_empty() && controls == 0 {
        return None;
    }
    // `-u HOME -u HOME` names one variable, and `-u CI CI=1` both removes and
    // writes one. Either way the set of names this prefix decided is what the
    // review reads.
    let mut seen = std::collections::BTreeSet::new();
    names.retain(|name| seen.insert(name.clone()));
    Some((next, names))
}

#[cfg(test)]
mod tests {
    use crate::{parse_command, CommandModelRequestV1};

    fn parse(command: &str) -> crate::CanonicalCommandV1 {
        parse_command(&CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap()
    }

    /// The `env` options that only decide which names the program starts
    /// with leave the program itself untouched, so the command models as the
    /// program it runs. Every name the prefix adds or removes joins
    /// `environment_names`, which is what keeps `PATH` under review.
    #[test]
    fn controls_that_only_name_the_environment_expose_the_program() {
        for (command, names) in [
            ("env -u NODE_OPTIONS npm test", vec!["NODE_OPTIONS"]),
            ("env --unset NODE_OPTIONS npm test", vec!["NODE_OPTIONS"]),
            ("env --unset=NODE_OPTIONS npm test", vec!["NODE_OPTIONS"]),
            ("env -uNODE_OPTIONS npm test", vec!["NODE_OPTIONS"]),
            ("env -u A -u B npm test", vec!["A", "B"]),
            ("env -u CI CI=1 npm test", vec!["CI"]),
            ("env -u NODE_OPTIONS -- npm test", vec!["NODE_OPTIONS"]),
            ("env -- npm test", vec![]),
        ] {
            let model = parse(command);
            assert_eq!(model.confidence, "exact", "{command}");
            assert_eq!(
                model.segments[0].executable.as_deref(),
                Some("npm"),
                "{command}"
            );
            assert_eq!(model.segments[0].environment_names, names, "{command}");
        }
        // Removing `PATH` leaves the program resolved against a search path
        // this text does not hold, the same question a written `PATH=` asks.
        assert!(parse("env -u PATH npm test").path_overridden);
    }

    /// A real `env` would remove these names and run the program behind them.
    /// Reading only a plain variable name is the narrower choice this parser
    /// makes, so they keep `env`'s own spelling and stay under review.
    #[test]
    fn a_name_this_parser_does_not_read_keeps_env_under_review() {
        for command in [
            "env -u -S '/bin/bash -c' 'rm -rf workspace/target'",
            "env -u 1BAD npm test",
            "env -u NODE-OPTIONS npm test",
            "env --unset= npm test",
            "env -u= npm test",
            "env -u",
            "env --",
        ] {
            let model = parse(command);
            assert!(
                model.confidence != "exact"
                    || model.segments[0].executable.as_deref() == Some("env"),
                "{command}: {:?}",
                model.segments.first().map(|segment| &segment.executable)
            );
        }
    }
}
