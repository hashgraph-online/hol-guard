//! Narrow interpreter classifications without attributing every CLI to secrets.
//!
//! This module does not authorize execution. Programs outside these exact
//! syntactic forms retain the pre-tool interpreter review requirement.

fn quoted_literal(value: &str) -> Option<(&str, &str)> {
    let quote = value.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate().skip(1) {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == quote {
            return Some((&value[1..index], value[index + 1..].trim()));
        }
    }
    None
}

fn literal_printer(script: &str, python: bool) -> bool {
    let script = script.trim();
    let function = if python { "print(" } else { "console.log(" };
    let Some(value) = script.strip_prefix(function) else {
        return false;
    };
    quoted_literal(value.trim()).is_some_and(|(_, remaining)| matches!(remaining, ")" | ");"))
}

fn compact_code(script: &str) -> String {
    let mut quote = None;
    let mut escaped = false;
    script
        .chars()
        .filter(|ch| {
            if escaped {
                escaped = false;
                return true;
            }
            if let Some(delimiter) = quote {
                if *ch == '\\' {
                    escaped = true;
                } else if *ch == delimiter {
                    quote = None;
                }
                return true;
            }
            if matches!(ch, '\'' | '"') {
                quote = Some(*ch);
            }
            !ch.is_whitespace()
        })
        .collect()
}

fn named_public_environment_read(script: &str, python: bool) -> bool {
    // Accept only a complete single read of a fixed public variable. A second
    // expression, dynamic lookup, default argument, or import stays unsupported.
    let compact = compact_code(script);
    let code = if python {
        compact.strip_prefix("importos;").unwrap_or(&compact)
    } else {
        &compact
    };
    let prefixes: &[&str] = if python {
        &[
            "print(os.getenv(",
            "print(os.environ.get(",
            "print(os.environ[",
        ]
    } else {
        &["console.log(process.env["]
    };
    for prefix in prefixes {
        let Some(value) = code.strip_prefix(prefix) else {
            continue;
        };
        let Some((name, remaining)) = quoted_literal(value) else {
            continue;
        };
        let close = if prefix.ends_with('[') { "])" } else { "))" };
        if (remaining == close || remaining.strip_suffix(';') == Some(close))
            && matches!(name, "PATH" | "HOME" | "PWD" | "SHELL" | "LANG" | "TERM")
        {
            return true;
        }
    }
    false
}

fn artisan_script(arguments: &[String]) -> bool {
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        if argument == "--" {
            index += 1;
            break;
        }
        if matches!(
            argument.as_str(),
            "-c" | "-d" | "-z" | "--define" | "--php-ini"
        ) {
            if arguments.get(index + 1).is_none() {
                return false;
            }
            index += 2;
        } else if argument == "-n"
            || ["-c", "-d", "-z"]
                .iter()
                .any(|flag| argument.starts_with(flag) && argument.len() > flag.len())
            || argument.starts_with("--define=")
            || argument.starts_with("--php-ini=")
        {
            index += 1;
        } else if argument.starts_with('-') {
            return false;
        } else {
            break;
        }
    }
    arguments
        .get(index)
        .is_some_and(|script| script.rsplit(['/', '\\']).next() == Some("artisan"))
}

/// None means no owned environment observation; Some records uncertainty.
pub(super) fn environment_observation(executable: &str, arguments: &[String]) -> Option<bool> {
    if executable == "php" && artisan_script(arguments) {
        // Artisan's command grammar has its own bounded extension matcher.
        return None;
    }
    if arguments.is_empty()
        || matches!(arguments, [only] if matches!(only.as_str(), "--version" | "--help" | "-h"))
    {
        return None;
    }
    let python = executable.starts_with("python");
    let node = matches!(executable, "node" | "nodejs");
    let script = arguments.windows(2).find_map(|pair| {
        matches!(pair[0].as_str(), "-c" | "-e" | "-p" | "-r").then_some(pair[1].as_str())
    });
    let Some(script) = script else {
        return Some(true);
    };
    if (python || node)
        && (literal_printer(script, python) || named_public_environment_read(script, python))
    {
        return None;
    }
    let compact = compact_code(script);
    let explicit = compact.contains("os.environ")
        || compact.contains("os.getenv(")
        || compact.contains("process.env")
        || compact.contains("ENV[")
        || compact.contains("System.getenv(");
    Some(!explicit)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(items: &[&str]) -> Vec<String> {
        items.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn modeled_cli_and_literal_output_do_not_invent_environment_access() {
        for (executable, args) in [
            ("php", vec!["artisan", "migrate"]),
            (
                "php",
                vec!["-d", "memory_limit=1G", "/app/artisan", "db:wipe"],
            ),
            (
                "python3",
                vec!["-c", "print('aws accessanalyzer delete-analyzer')"],
            ),
            ("python3", vec!["-c", "import os; print(os.getenv('PATH'))"]),
            ("node", vec!["-e", "console.log('process.env')"]),
        ] {
            assert_eq!(environment_observation(executable, &arguments(&args)), None);
        }
    }

    #[test]
    fn secret_lookups_and_unknown_programs_retain_owned_review() {
        for script in [
            "import os; print(os.environ)",
            "import os; print(os.getenv('GOOGLE_CLOUD_PRIVATE_KEY'))",
            "print(os.environ['TOKEN'])",
            "import os; print(os.getenv('PATH')); print(os.environ)",
        ] {
            assert_eq!(
                environment_observation("python3", &arguments(&["-c", script])),
                Some(false)
            );
        }
        assert_eq!(
            environment_observation("python3", &arguments(&["script.py"])),
            Some(true)
        );
        assert_eq!(
            environment_observation("php", &arguments(&["-r", "artisan"])),
            Some(true)
        );
    }
}
