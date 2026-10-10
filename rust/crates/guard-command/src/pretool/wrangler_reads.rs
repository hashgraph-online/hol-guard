//! Read-only Cloudflare Wrangler invocations.
//!
//! Only metadata, help and the signed-in identity are admitted. Every other
//! subcommand or flag can deploy, mutate remote resources or load project code
//! and keeps the normal review path.

pub(super) fn safe_wrangler_arguments(arguments: &[String]) -> bool {
    match arguments {
        [flag] => matches!(
            flag.as_str(),
            "--version" | "-v" | "--help" | "-h" | "whoami"
        ),
        [path @ .., flag] if matches!(flag.as_str(), "--help" | "-h") => {
            !path.is_empty() && path.len() <= 3 && path.iter().all(|word| subcommand_word(word))
        }
        _ => false,
    }
}

fn subcommand_word(word: &str) -> bool {
    let mut characters = word.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | ':')
        })
}

#[cfg(test)]
mod tests {
    use super::safe_wrangler_arguments;

    fn arguments(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn admits_only_metadata_help_and_identity() {
        for command in [
            "--version",
            "-v",
            "--help",
            "-h",
            "whoami",
            "deploy --help",
            "d1 execute -h",
            "kv:namespace list --help",
            "pages project delete --help",
        ] {
            assert!(safe_wrangler_arguments(&arguments(command)), "{command}");
        }
        for command in [
            "",
            "deploy",
            "whoami --account x",
            "--version --config other.toml",
            "--help deploy",
            "deploy --dry-run --help",
            "d1 execute db --command DROP --help",
            "Deploy --help",
            "./script --help",
            "a b c d --help",
            "dev",
            "tail",
            "types",
            "login",
        ] {
            assert!(!safe_wrangler_arguments(&arguments(command)), "{command}");
        }
    }
}
