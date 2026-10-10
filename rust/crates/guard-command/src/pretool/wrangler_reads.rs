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

/// `npx wrangler <read-only args>` runs the project's own installed Wrangler.
///
/// `npx` downloads and runs a package it cannot find locally, so the proof
/// requires the exact package name as the first argument (no `--yes`, `-p`,
/// version suffix or other npx flag) and a local `node_modules/.bin/wrangler`
/// symlink into `node_modules/wrangler/` at the nearest project root, which is
/// where npx looks first. A pnpm shim script or a missing install keeps review.
pub(super) fn safe_npx_wrangler(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let Some((package, rest)) = arguments.split_first() else {
        return false;
    };
    package == "wrangler"
        && safe_wrangler_arguments(rest)
        && super::safe_reads::verified_path_context(context.home_dir, context.cwd)
        && context
            .cwd
            .is_some_and(|cwd| local_wrangler_installed(cwd, context.home_dir))
}

fn local_wrangler_installed(cwd: &str, home_dir: Option<&str>) -> bool {
    let cwd = match (cwd, home_dir) {
        ("~", Some(home)) => std::path::PathBuf::from(home),
        (_, Some(home)) if cwd.starts_with("~/") => std::path::Path::new(home).join(&cwd[2..]),
        _ => std::path::PathBuf::from(cwd),
    };
    let Ok(cwd) = std::fs::canonicalize(cwd) else {
        return false;
    };
    // npm's local prefix is the nearest ancestor with a manifest or modules dir.
    let Some(project) = cwd
        .ancestors()
        .take(32)
        .find(|dir| dir.join("package.json").is_file() || dir.join("node_modules").is_dir())
    else {
        return false;
    };
    let Ok(target) = std::fs::read_link(project.join("node_modules/.bin/wrangler")) else {
        return false;
    };
    target
        .to_str()
        .is_some_and(|target| target.starts_with("../wrangler/") && !target.contains("/../"))
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
