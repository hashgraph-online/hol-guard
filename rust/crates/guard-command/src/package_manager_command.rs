//! `package_manager_command.py` — normalize package-manager commands before
//! install/execute parsing (166 lines — verbatim port).

use std::sync::LazyLock;

struct GlobalOptionConfig {
    subcommands: &'static [&'static str],
    value_options: &'static [&'static str],
}

static MANAGER_ALIASES: &[(&str, &str)] = &[("pip3", "pip")];

static MANAGER_GLOBAL_OPTIONS: LazyLock<Vec<(&'static str, GlobalOptionConfig)>> =
    LazyLock::new(|| {
        vec![
            (
                "npm",
                GlobalOptionConfig {
                    subcommands: &["add", "audit", "ci", "exec", "i", "install", "update", "x"],
                    value_options: &[
                        "--cache",
                        "--config",
                        "--prefix",
                        "--registry",
                        "--userconfig",
                        "-C",
                    ],
                },
            ),
            (
                "pnpm",
                GlobalOptionConfig {
                    subcommands: &["add", "dlx", "i", "install"],
                    value_options: &[
                        "--dir",
                        "--filter",
                        "--registry",
                        "--store-dir",
                        "--workspace-dir",
                        "-C",
                        "-F",
                    ],
                },
            ),
            (
                "yarn",
                GlobalOptionConfig {
                    subcommands: &["add", "dlx", "install", "up", "workspace"],
                    value_options: &["--cache-folder", "--cwd", "--modules-folder", "--registry"],
                },
            ),
            (
                "pip",
                GlobalOptionConfig {
                    subcommands: &["install"],
                    value_options: &[
                        "--cache-dir",
                        "--cert",
                        "--client-cert",
                        "--extra-index-url",
                        "--find-links",
                        "--index-url",
                        "--proxy",
                        "--python",
                        "--retries",
                        "--timeout",
                        "--trusted-host",
                        "-f",
                        "-i",
                    ],
                },
            ),
            (
                "pipx",
                GlobalOptionConfig {
                    subcommands: &["install", "run"],
                    value_options: &["--index-url", "--pip-args", "--python"],
                },
            ),
            (
                "uv",
                GlobalOptionConfig {
                    subcommands: &["add", "pip", "sync"],
                    value_options: &[
                        "--cache-dir",
                        "--directory",
                        "--index",
                        "--python",
                        "--project",
                    ],
                },
            ),
            (
                "brew",
                GlobalOptionConfig {
                    subcommands: &["bundle", "install", "reinstall", "tap", "upgrade"],
                    value_options: &["--cache", "--cellar", "--prefix", "--repository"],
                },
            ),
            (
                "poetry",
                GlobalOptionConfig {
                    subcommands: &["add", "install"],
                    value_options: &["--directory", "-C"],
                },
            ),
            (
                "pipenv",
                GlobalOptionConfig {
                    subcommands: &["install", "sync"],
                    value_options: &["--python"],
                },
            ),
        ]
    });

/// Options that change only how a manager reports its work, never which bytes
/// it installs or where they land. The approval binding drops them so a saved
/// allow for `uv sync --frozen` still covers `uv sync -q --frozen`.
static PRESENTATION_OPTIONS: &[&str] = &[
    "--no-ansi",
    "--no-color",
    "--no-progress",
    "--quiet",
    "--silent",
    "--verbose",
    "-q",
    "-qq",
    "-qqq",
    "-v",
    "-vv",
    "-vvv",
];

/// Inline-valued forms of the same reporting options.
static PRESENTATION_VALUE_PREFIXES: &[&str] = &[
    "--color=",
    "--log-level=",
    "--loglevel=",
    "--progress=",
    "--verbosity=",
];

/// Verbs that hand the rest of the command line to another program. A `-v`
/// after one of these belongs to that program, where it can mean anything
/// (`grep -v` inverts the match), so those commands keep their exact spelling.
static DOWNSTREAM_PROGRAM_VERBS: &[(&str, &[&str])] = &[
    ("npm", &["exec", "x"]),
    ("pnpm", &["dlx", "exec"]),
    ("yarn", &["dlx", "exec"]),
    ("pipx", &["run"]),
    ("uv", &["run", "tool"]),
];

/// Managers that are themselves a runner for another program.
static DOWNSTREAM_PROGRAM_MANAGERS: &[&str] = &["bunx", "npx", "pnpx", "uvx"];

fn is_presentation_option(token: &str) -> bool {
    PRESENTATION_OPTIONS.contains(&token)
        || PRESENTATION_VALUE_PREFIXES
            .iter()
            .any(|prefix| token.starts_with(prefix))
}

/// Drop reporting-only options from a package manager's arguments.
///
/// `arguments` is the command line after the executable, the way
/// `PackageExecutionContext` passes it to the launch identity. The result feeds
/// the approval binding only: the review card still shows the command exactly
/// as it was typed. Returns the arguments unchanged for an unknown manager, for
/// a runner that executes another program, and for everything after a bare
/// `--`.
pub fn strip_manager_presentation_arguments(manager: &str, arguments: &[String]) -> Vec<String> {
    let key = manager_key(manager);
    if DOWNSTREAM_PROGRAM_MANAGERS.contains(&key.as_str()) || manager_config(&key).is_none() {
        return arguments.to_vec();
    }
    let downstream = DOWNSTREAM_PROGRAM_VERBS
        .iter()
        .find(|(name, _)| *name == key)
        .map_or(&[] as &[&str], |(_, verbs)| *verbs);
    let mut stripped: Vec<String> = Vec::with_capacity(arguments.len());
    let mut in_manager_options = true;
    for token in arguments {
        if in_manager_options {
            if token == "--" {
                in_manager_options = false;
            } else if downstream.contains(&token.as_str()) {
                return arguments.to_vec();
            } else if is_presentation_option(token) {
                continue;
            }
        }
        stripped.push(token.clone());
    }
    stripped
}

fn manager_config(name: &str) -> Option<&'static GlobalOptionConfig> {
    let key = manager_key(name);
    MANAGER_GLOBAL_OPTIONS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// `strip_package_manager_global_options` (:102-119).
pub fn strip_package_manager_global_options(tokens: &[String]) -> Vec<String> {
    let normalized_tokens: Vec<String> = tokens.iter().map(|t| t.to_string()).collect();
    if normalized_tokens.len() < 2 {
        return normalized_tokens;
    }
    let Some(config) = manager_config(&normalized_tokens[0]) else {
        return normalized_tokens;
    };
    let mut index = 1usize;
    while index < normalized_tokens.len() {
        let token = &normalized_tokens[index];
        if config.subcommands.contains(&token.as_str()) {
            let mut out = vec![normalized_tokens[0].clone()];
            out.extend_from_slice(&normalized_tokens[index..]);
            return out;
        }
        if token == "--" {
            break;
        }
        if !token.starts_with('-') {
            let mut out = vec![normalized_tokens[0].clone()];
            out.extend_from_slice(&normalized_tokens[index..]);
            return out;
        }
        index += leading_option_width(&normalized_tokens, index, config);
    }
    normalized_tokens
}

/// `_manager_key` (:122-124). `Path(command_name).name.lower()` → basename,
/// lowercase; `pip3` → `pip` alias.
fn manager_key(command_name: &str) -> String {
    let normalized = command_name
        .rsplit('/')
        .next()
        .unwrap_or(command_name)
        .to_lowercase();
    MANAGER_ALIASES
        .iter()
        .find(|(k, _)| *k == normalized)
        .map(|(_, v)| (*v).to_owned())
        .unwrap_or(normalized)
}

/// `_leading_option_width` (:127-157).
fn leading_option_width(tokens: &[String], index: usize, config: &GlobalOptionConfig) -> usize {
    let token = &tokens[index];
    let next_index = index + 1;
    let has_next = next_index < tokens.len();
    if has_next && config.subcommands.contains(&tokens[next_index].as_str()) {
        return 1;
    }
    if config.value_options.contains(&token.as_str()) {
        return if has_next { 2 } else { 1 };
    }
    if matches_inline_value_option(token, config.value_options) {
        return 1;
    }
    let next_token: Option<&str> = tokens.get(next_index).map(|s| s.as_str());
    if token.starts_with("--") {
        if !token.contains('=')
            && next_token.is_some()
            && !next_token.unwrap().starts_with('-')
            && !config.subcommands.contains(&next_token.unwrap())
        {
            return 2;
        }
        return 1;
    }
    if token.len() == 2
        && next_token.is_some()
        && !next_token.unwrap().starts_with('-')
        && !config.subcommands.contains(&next_token.unwrap())
    {
        return 2;
    }
    1
}

/// `_matches_inline_value_option` (:160-166).
fn matches_inline_value_option(token: &str, value_options: &[&str]) -> bool {
    for option in value_options {
        if option.starts_with("--") && token.starts_with(&format!("{option}=")) {
            return true;
        }
        if option.starts_with('-')
            && !option.starts_with("--")
            && token.starts_with(option)
            && token != *option
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn npm_global_registry_stripped() {
        let got = strip_package_manager_global_options(&t(&[
            "npm",
            "--registry",
            "https://r",
            "install",
            "lodash",
        ]));
        assert_eq!(got, t(&["npm", "install", "lodash"]));
    }

    #[test]
    fn pip3_alias_maps_to_pip() {
        let got = strip_package_manager_global_options(&t(&[
            "pip3",
            "-i",
            "https://i",
            "install",
            "flask",
        ]));
        assert_eq!(got, t(&["pip3", "install", "flask"]));
    }

    #[test]
    fn unknown_manager_passthrough() {
        let got = strip_package_manager_global_options(&t(&["cargo", "--flag", "install"]));
        assert_eq!(got, t(&["cargo", "--flag", "install"]));
    }

    #[test]
    fn bare_tokens_under_two_passthrough() {
        let got = strip_package_manager_global_options(&t(&["npm"]));
        assert_eq!(got, t(&["npm"]));
    }

    #[test]
    fn a_quiet_spelling_binds_like_the_loud_one() {
        assert_eq!(
            strip_manager_presentation_arguments(
                "uv",
                &t(&["sync", "-q", "--frozen", "--extra", "dev"])
            ),
            t(&["sync", "--frozen", "--extra", "dev"]),
        );
    }

    #[test]
    fn installation_affecting_options_are_kept() {
        let args = t(&[
            "sync",
            "--frozen",
            "--group",
            "ci-test",
            "--no-install-project",
            "--python",
            "3.12",
        ]);
        assert_eq!(strip_manager_presentation_arguments("uv", &args), args);
    }

    #[test]
    fn inline_reporting_values_are_dropped() {
        assert_eq!(
            strip_manager_presentation_arguments(
                "npm",
                &t(&["install", "--loglevel=silly", "--no-progress", "lodash"])
            ),
            t(&["install", "lodash"]),
        );
    }

    #[test]
    fn a_runner_keeps_its_programs_own_flags() {
        let uvx = t(&["ruff", "check", "-q", "src"]);
        assert_eq!(strip_manager_presentation_arguments("uvx", &uvx), uvx);
        let uv_run = t(&["run", "ruff", "check", "-q", "src"]);
        assert_eq!(strip_manager_presentation_arguments("uv", &uv_run), uv_run);
        let npm_exec = t(&["exec", "--", "eslint", "-q"]);
        assert_eq!(
            strip_manager_presentation_arguments("npm", &npm_exec),
            npm_exec
        );
    }

    #[test]
    fn nothing_after_a_bare_separator_is_touched() {
        assert_eq!(
            strip_manager_presentation_arguments("npm", &t(&["install", "-q", "--", "-v"])),
            t(&["install", "--", "-v"]),
        );
    }

    #[test]
    fn an_unknown_manager_is_left_alone() {
        let args = t(&["install", "-q", "ripgrep"]);
        assert_eq!(strip_manager_presentation_arguments("cargo", &args), args);
    }

    #[test]
    fn a_manager_alias_is_resolved_before_stripping() {
        assert_eq!(
            strip_manager_presentation_arguments("pip3", &t(&["install", "-q", "requests"])),
            t(&["install", "requests"]),
        );
    }

    #[test]
    fn inline_value_option_consumed() {
        let got = strip_package_manager_global_options(&t(&[
            "npm",
            "--registry=https://r",
            "install",
            "x",
        ]));
        assert_eq!(got, t(&["npm", "install", "x"]));
    }
}
