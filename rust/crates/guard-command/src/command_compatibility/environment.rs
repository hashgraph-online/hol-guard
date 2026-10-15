//! Assignment prefixes (`NAME=value cmd`) the compatibility layer can attribute.
//!
//! A prefix only changes the program's environment, so the observed program
//! and arguments still describe the command when the name is inert. A name
//! that can point the program, its compiler or its loader at other code
//! (`NODE_PATH`, `RUSTFLAGS`, `RUSTC_WRAPPER`, `CC`, `LD_PRELOAD`, ...) is
//! matched by name fragment rather than a closed list and fails closed. Any
//! other name (`PORT`, `GIT_DIR`, `KUBECONFIG`, `HOME`) stays uncertainty for the
//! owners' floor.

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

/// The author and committer identity Git records in a new commit. Git reads
/// them only as text for the commit header, so they cannot choose a
/// repository, a configuration file or a program for Git to run. Every other
/// `GIT_*` name (`GIT_DIR`, `GIT_CONFIG_*`, `GIT_PAGER`, `GIT_SSH_COMMAND`,
/// ...) can, and stays non-inert.
pub(crate) fn git_identity_environment_name(name: &str) -> bool {
    matches!(
        name,
        "GIT_AUTHOR_NAME"
            | "GIT_AUTHOR_EMAIL"
            | "GIT_AUTHOR_DATE"
            | "GIT_COMMITTER_NAME"
            | "GIT_COMMITTER_EMAIL"
            | "GIT_COMMITTER_DATE"
    )
}

/// Variables that hold locations, the session's identity or display
/// settings, never a credential, so printing them by name shows no secret.
/// A name that fits no pattern here, such as `DATABASE_URL`, stays reviewed.
pub(crate) fn plain_printed_name(name: &str) -> bool {
    let word = |c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_';
    if name.is_empty() || !name.chars().all(word) || credential_routing_environment_name(name) {
        return false;
    }
    inert_environment_name(name)
        || matches!(
            name,
            "PATH"
                | "HOME"
                | "PWD"
                | "OLDPWD"
                | "SHELL"
                | "SHLVL"
                | "USER"
                | "LOGNAME"
                | "HOSTNAME"
                | "TMPDIR"
                | "EDITOR"
                | "VISUAL"
                | "PAGER"
                | "TERM_PROGRAM"
                | "COLORTERM"
                | "VIRTUAL_ENV"
                | "CONDA_PREFIX"
        )
        || name.ends_with("_HOME")
        || name.ends_with("PATH")
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

/// Name fragments of settings that make a program, its compiler or its loader
/// run other code or options, or search elsewhere for it (`NODE_OPTIONS`,
/// `RUSTFLAGS`, `RUSTC_WRAPPER`, `PYTHONSTARTUP`, `CLASSPATH`). A data path
/// such as `OUTPUT_PATH` cannot be told apart by name, so it fails closed too.
const CODE_LOADING_MARKERS: &[&str] = &[
    "ARGS",
    "BIN",
    "BROWSER",
    "CMD",
    "COMMAND",
    "EDITOR",
    "EXEC",
    "FLAGS",
    "HOOK",
    "IMPORT",
    "INIT",
    "LIB",
    "LOAD",
    "MODULE",
    "OPT",
    "PAGER",
    "PLUGIN",
    "REQUIRE",
    "LINKER",
    "RUNNER",
    "RUSTC",
    "RUSTDOC",
    "SCRIPT",
    "SHELL",
    "STARTUP",
    "VISUAL",
    "WRAPPER",
    "USERBASE",
    "GEMFILE",
    "LESSOPEN",
    "LESSCLOSE",
    "PATH",
];

/// Fragments of settings that move where a program finds its config or home
/// (`KUBECONFIG`, `XDG_CONFIG_HOME`, `HOME`). Most name data, so the
/// compatibility layer reviews them as uncertainty while the env-prefix
/// projection still declines them.
const REDIRECT_MARKERS: &[&str] = &["CONF", "HOME"];

/// Toolchain programs a build reads from the environment.
const CODE_LOADING_NAMES: &[&str] = &[
    "AR", "AS", "CC", "CPP", "CXX", "FC", "LD", "LINK", "NM", "RANLIB",
];

/// Exact names a program, its shell or Git runs as code or reads a toolchain
/// or interpreter home from, which no marker above covers.
const CODE_LOADING_EXACT: &[&str] = &[
    "BASH_ENV",
    "CARGO_HOME",
    "ENV",
    "GEM_HOME",
    "GIT_ASKPASS",
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH",
    "GOROOT",
    "GOTOOLCHAIN",
    "JAVA_HOME",
    "PYTHONHOME",
    "RUSTUP_HOME",
    "SSH_ASKPASS",
];

/// A setting that points a program, its compiler, its loader or its shell at
/// other code (`NODE_OPTIONS`, `RUSTC_WRAPPER`, `npm_config_script_shell`,
/// `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `CXX`). It is matched by fragment,
/// not by a closed list, so new wrapper and loader names fail closed too.
pub(crate) fn code_loading_environment_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let upper = upper.as_str();
    CODE_LOADING_NAMES.contains(&upper)
        || CODE_LOADING_EXACT.contains(&upper)
        || ["LD_", "DYLD_", "BASH_FUNC_", "NPM_CONFIG_"]
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        || CODE_LOADING_MARKERS
            .iter()
            .any(|marker| upper.contains(marker))
}

/// A code-loading setting, or one that redirects config or home. The
/// env-prefix projection never strips either kind.
pub(crate) fn code_or_redirect_environment_name(name: &str) -> bool {
    code_loading_environment_name(name) || {
        let upper = name.to_ascii_uppercase();
        REDIRECT_MARKERS.iter().any(|marker| upper.contains(marker))
    }
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
    fn code_loading_names_leave_the_context_unsupported() {
        for program in ["cargo", "java", "./gradlew", "go", "npm", "kd"] {
            for name in [
                "RUSTC_WRAPPER",
                "CARGO_BUILD_RUSTC_WRAPPER",
                "RUSTDOC",
                "CARGO_BUILD_RUSTDOC",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
                "npm_config_shell",
                "npm_config_registry",
                "npm_config_script_shell",
                "LD_LIBRARY_PATH",
                "DYLD_INSERT_LIBRARIES",
                "CLASSPATH",
                "LUA_PATH",
                "GEM_PATH",
                "GOPATH",
                "PYTHONHOME",
                "RUSTUP_HOME",
                "JAVA_HOME",
                "CARGO_HOME",
                "GOTOOLCHAIN",
                "KD_SAVE_PATH",
            ] {
                let unsupported = super::super::assignment_prefix_is_unsupported(&segment(
                    program,
                    &["CI", name],
                ));
                assert!(unsupported, "{program}: {name}");
            }
            for name in [
                "PORT",
                "APP_FLAG",
                "VITE_BASE",
                "KUBECONFIG",
                "HOME",
                "GIT_DIR",
            ] {
                let unsupported =
                    super::super::assignment_prefix_is_unsupported(&segment(program, &[name]));
                assert!(!unsupported, "{program}: {name}");
            }
        }
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

    #[test]
    fn printed_names_are_plain_only_without_a_credential_word() {
        for name in [
            "PATH",
            "HOME",
            "USER",
            "LC_ALL",
            "JAVA_HOME",
            "PYTHONPATH",
            "NODE_ENV",
        ] {
            assert!(plain_printed_name(name), "{name}");
        }
        for name in [
            "DATABASE_URL",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "TOKEN_PATH",
            "path",
            "-0",
            "",
        ] {
            assert!(!plain_printed_name(name), "{name}");
        }
    }
}
