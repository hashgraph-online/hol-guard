//! Assignment prefixes (`NAME=value cmd`) the compatibility layer can attribute.
//!
//! A prefix only changes the program's environment, so the observed program
//! and arguments still describe the command when the name is inert. Any other
//! name can point the program, its compiler or its loader at other code
//! (`NODE_PATH`, `RUSTFLAGS`, `GOFLAGS`, `CC`, `LD_PRELOAD`, ...). No denylist
//! can name all of those, so only an allowlist of inert names is accepted.

#[cfg(test)]
use crate::CommandSegmentV1;

/// Names that only adjust output, locale or a build mode.
pub(crate) fn inert_environment_name(name: &str) -> bool {
    matches!(
        name,
        "CI" | "NODE_ENV"
            | "FORCE_COLOR"
            | "NO_COLOR"
            | "CLICOLOR"
            | "CLICOLOR_FORCE"
            | "TERM"
            | "TZ"
            | "LANG"
            | "LANGUAGE"
            | "COLUMNS"
            | "LINES"
            | "DEBUG"
            | "NODE_NO_WARNINGS"
            | "RUST_LOG"
            | "RUST_BACKTRACE"
            | "PYTHONUNBUFFERED"
            | "PYTHONDONTWRITEBYTECODE"
    ) || name.starts_with("LC_")
}

/// Whole-word credential names, plus the pairs `API_KEY` and `CONFIG_DIR`.
/// `GH_TOKEN`, `GOOGLE_APPLICATION_CREDENTIALS`, `GOG_KEYRING_PASSWORD`, and
/// `GH_CONFIG_DIR` match, so that prefix is not a reviewable context.
/// `XDG_CONFIG_HOME`, `KUBECONFIG`, `AWS_PROFILE`, `AWS_CONFIG_FILE`,
/// `DOCKER_CONFIG`, `CLOUDSDK_CONFIG`, `NETRC`, and `HOME` do not match and
/// stay on the uncertainty floor. `TOKENIZERS_PARALLELISM` does not match:
/// its word is `TOKENIZERS`, not `TOKEN`.
pub(crate) fn credential_routing_environment_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let words: Vec<&str> = upper.split('_').collect();
    words.iter().any(|word| {
        matches!(
            *word,
            "TOKEN"
                | "CREDENTIAL"
                | "CREDENTIALS"
                | "SECRET"
                | "PASSWORD"
                | "PASSPHRASE"
                | "APIKEY"
        )
    }) || words.windows(2).any(|pair| {
        matches!(
            (pair[0], pair[1]),
            ("API" | "ACCESS" | "PRIVATE", "KEY") | ("CONFIG", "DIR")
        )
    })
}

#[cfg(test)]
pub(super) fn supported(segment: &CommandSegmentV1) -> bool {
    segment
        .environment_names
        .iter()
        .all(|name| inert_environment_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(executable: &str, names: &[&str]) -> CommandSegmentV1 {
        let prefix: String = names.iter().map(|name| format!("{name}=1 ")).collect();
        let model = crate::parse_command(
            &serde_json::from_value(
                serde_json::json!({"command": format!("{prefix}{executable} run")}),
            )
            .unwrap(),
        )
        .unwrap();
        model.segments.into_iter().next().unwrap()
    }

    #[test]
    fn inert_names_are_supported_on_every_program() {
        for program in ["git", "gh", "bun", "curl"] {
            assert!(supported(&segment(program, &["CI", "LC_ALL", "NO_COLOR"])));
        }
    }

    #[test]
    fn credential_routing_names_are_whole_words() {
        for name in [
            "GH_TOKEN",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE",
            "GOOGLE_WORKSPACE_CLI_CLIENT_SECRET",
            "GOOGLE_WORKSPACE_CLI_CONFIG_DIR",
            "GOG_KEYRING_PASSWORD",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "gh_config_dir",
        ] {
            assert!(credential_routing_environment_name(name), "{name}");
        }
        for name in [
            "TOKENIZERS_PARALLELISM",
            "CI",
            "XDG_CONFIG_HOME",
            "KUBECONFIG",
            "AWS_PROFILE",
            "AWS_CONFIG_FILE",
            "DOCKER_CONFIG",
            "CLOUDSDK_CONFIG",
            "NETRC",
            "HOME",
            "KEYBOARD",
            "TODO_FILE",
        ] {
            assert!(!credential_routing_environment_name(name), "{name}");
        }
    }

    #[test]
    fn every_other_name_stays_unsupported() {
        for program in ["bun", "node", "cargo", "go", "make", "git", "curl"] {
            for name in [
                "APP_FLAG",
                "NODE_PATH",
                "NODE_OPTIONS",
                "BUN_OPTIONS",
                "LD_PRELOAD",
                "DYLD_INSERT_LIBRARIES",
                "GIT_SSH_COMMAND",
                "HOME",
                "npm_config_script_shell",
                "XDG_CONFIG_HOME",
                "PYTHONPATH",
                "PYTHONBREAKPOINT",
                "RUSTFLAGS",
                "RUSTDOCFLAGS",
                "GOFLAGS",
                "CC",
                "CXX",
                "MAKEFLAGS",
                "GCONV_PATH",
            ] {
                assert!(!supported(&segment(program, &[name])), "{program}: {name}");
                assert!(
                    !supported(&segment(program, &["CI", name])),
                    "{program}: CI {name}"
                );
            }
        }
    }
}
