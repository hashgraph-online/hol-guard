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
                // Where a toolchain is installed or builds its output.
                | "BUN_INSTALL"
                | "NVM_DIR"
                | "NVM_BIN"
                | "PYENV_ROOT"
                | "RBENV_ROOT"
                | "GOROOT"
                | "GOBIN"
                | "CARGO_TARGET_DIR"
                | "XDG_RUNTIME_DIR"
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
    "ARGS", "BIN", "BROWSER", "CMD", "COMMAND", "EDITOR", "EXEC", "FLAGS", "HOOK", "IMPORT",
    "INIT", "LIB", "LOAD", "MODULE", "OPT", "PAGER", "PLUGIN", "REQUIRE", "LINKER", "RUNNER",
    "RUSTC", "RUSTDOC", "SCRIPT", "SHELL", "STARTUP", "VISUAL", "WRAPPER", "USERBASE", "GEMFILE",
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
/// or interpreter home from, which no marker above covers. `MORE` and `LV`
/// carry a pager's start-up options, and those options include the shell
/// escape that runs a command of their own.
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
    "LV",
    "MORE",
    "PYTHONHOME",
    "RUSTUP_HOME",
    "SSH_ASKPASS",
];

/// A setting that points a program, its compiler, its loader or its shell at
/// other code (`NODE_OPTIONS`, `RUSTC_WRAPPER`, `npm_config_script_shell`,
/// `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `CXX`). It is matched by fragment,
/// not by a closed list, so new wrapper and loader names fail closed too.
/// The whole `LESS*` family is spelled as a prefix: `LESS` itself holds the
/// options `less` starts with, and `LESS=+!cmd` makes the pager run `cmd`
/// before it shows a line, so the bare name redirects execution as surely as
/// `LESSOPEN` does.
pub(crate) fn code_loading_environment_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let upper = upper.as_str();
    CODE_LOADING_NAMES.contains(&upper)
        || CODE_LOADING_EXACT.contains(&upper)
        || ["LD_", "DYLD_", "BASH_FUNC_", "NPM_CONFIG_", "LESS"]
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        || CODE_LOADING_MARKERS
            .iter()
            .any(|marker| upper.contains(marker))
}

/// Fragments of settings that choose which certificates a later program
/// trusts, or whether it verifies them at all (`SSL_CERT_FILE`,
/// `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `PGSSLMODE`). None of them names
/// code, a config file or a home, so the markers above let them through,
/// while the value they carry decides whose certificate a later fetch
/// accepts.
const TRUST_ANCHOR_MARKERS: &[&str] = &[
    "CAINFO",
    "CAPATH",
    "CA_BUNDLE",
    "CA_CERT",
    "CERT",
    "SSL",
    "TLS",
];

/// A setting that moves the trust anchor of a program that runs later. A
/// binding outlives the list item that made it, so one of these names
/// decides whom the rest of the command believes.
pub(crate) fn trust_anchor_environment_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    TRUST_ANCHOR_MARKERS
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

/// Fragments of settings that move where a later program connects: a host,
/// a port, a database endpoint, a package index or a mirror. None of them
/// names code, a config file, a home or a trust anchor, so the markers above
/// let them through, while the value they carry decides whose server answers.
/// `PG*` is spelled as a prefix because libpq settings (`PGHOST`, `PGUSER`,
/// `PGSERVICE`) steer a connection under names that carry no marker word.
const ENDPOINT_MARKERS: &[&str] = &[
    "ADDR", "DSN", "ENDPOINT", "HOST", "INDEX", "MIRROR", "PORT", "PROXY", "REGISTRY", "SERVER",
    "URI", "URL",
];

/// A setting that redirects where a later program connects.
pub(crate) fn endpoint_steering_environment_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("PG") || ENDPOINT_MARKERS.iter().any(|marker| upper.contains(marker))
}

/// A setting whose whole effect is a value the command reads for itself:
/// either a known-inert name such as `CI` or `NODE_ENV`, or an ordinary
/// project name that steers nothing. Every family that can redirect what
/// runs — lookup, loading, config, home, credentials, the trust anchor and
/// the endpoint — keeps its signal, so a caller can treat the rest as a
/// value and nothing more.
pub(crate) fn ordinary_setting_name(name: &str) -> bool {
    !trust_anchor_environment_name(name)
        && !endpoint_steering_environment_name(name)
        && !credential_routing_environment_name(name)
        && (inert_environment_name(name)
            || (crate::pretool::generic::chain_literals::ordinary_name(name)
                && !code_or_redirect_environment_name(name)))
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
            "BUN_INSTALL",
            "NVM_DIR",
        ] {
            assert!(plain_printed_name(name), "{name}");
        }
        for name in [
            "DATABASE_URL",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "TOKEN_PATH",
            "BUN_AUTH_TOKEN",
            "NPM_CONFIG_DIR",
            "path",
            "-0",
            "",
        ] {
            assert!(!plain_printed_name(name), "{name}");
        }
    }
}
