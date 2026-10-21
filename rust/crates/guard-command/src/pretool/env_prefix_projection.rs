//! Agents routinely prefix a command with inert environment settings
//! (`LC_ALL=C ls`, `env -u GH_TOKEN gh api ...`, `GH_TOKEN= gh repo view`).
//! The canonical parser treats any prefix as unmodeled context, which made
//! the whole command fail closed. This projection removes only prefixes that
//! cannot change how the remaining command runs, so the remaining command is
//! judged on its own merits. Any prefix that can redirect execution, config,
//! credentials, code loading or network routing leaves the command untouched.

use crate::cloud_scrub_shell::{shell_tokens, ShellToken};
use crate::pretool::PathContext;

#[path = "env_prefix_reviewed.rs"]
mod reviewed;
#[path = "env_prefix_search_path.rs"]
mod search_path;
pub(super) use reviewed::join_reviewed;

const MAX_PROJECTED_CHARS: usize = 32_768;

/// Command separators after which a new simple command starts.
const COMMAND_SEPARATORS: [&str; 6] = ["|", "||", "&&", ";", "&", "|&"];

/// Exact settings that only quiet a tool, accepted despite a denied prefix.
const QUIETING_SETTINGS: [(&str, &str); 11] = [
    ("GH_NO_UPDATE_NOTIFIER", "1"),
    ("GH_PAGER", "cat"),
    ("GH_PAGER", ""),
    ("GH_PROMPT_DISABLED", "1"),
    ("GH_PROMPT_DISABLED", "true"),
    ("GIT_OPTIONAL_LOCKS", "0"),
    ("GIT_PAGER", "cat"),
    ("GIT_PAGER", ""),
    ("GIT_TERMINAL_PROMPT", "0"),
    ("PAGER", "cat"),
    ("PAGER", ""),
];

/// Settings that only shape output, locale or time.
const PRESENTATION_NAMES: [&str; 12] = [
    "CI",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "COLORTERM",
    "COLUMNS",
    "FORCE_COLOR",
    "LANG",
    "LANGUAGE",
    "LINES",
    "NO_COLOR",
    "TERM",
    "TZ",
];

const MAX_SCALAR_CHARS: usize = 128;

const CREDENTIAL_MARKERS: [&str; 8] = [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "AUTH",
    "CREDENTIAL",
    "PRIVATE_KEY",
];

/// Prefixes that can swap the program, hijack its loader or shell, or hand
/// it credentials. A command with one keeps its own unprojected verdict even
/// on the reviewed path.
const UNREVIEWABLE_NAMES: [&str; 12] = [
    "BASH_ENV",
    "CDPATH",
    "ENV",
    "FPATH",
    "HOME",
    "IFS",
    "PATH",
    "PROMPT_COMMAND",
    "PS4",
    "SHELL",
    "SHELLOPTS",
    "ZDOTDIR",
];

const UNREVIEWABLE_PREFIXES: [&str; 22] = [
    "ANTHROPIC_",
    "AWS_",
    "AZURE_",
    "BASH_FUNC_",
    "CLAUDE",
    "CLOUDSDK_",
    "CODEX_",
    "DOCKER_",
    "DYLD_",
    "GCLOUD_",
    "GH_",
    "GIT",
    "GOOGLE_",
    "GUARD_",
    "HOL_",
    "KUBE",
    "LD_",
    "OPENAI_",
    "SSH_",
    "SUDO_",
    "XDG_",
    "ZSH",
];

const MAX_SETTING_CHARS: usize = 40;

/// A command whose leading environment settings were removed although one of
/// them may change how it runs. It never earns less than review.
pub(super) struct ReviewedProjection {
    pub(super) command: String,
    /// The first setting that is not inert, a shape-checked variable name.
    pub(super) setting: String,
    /// Whether every such setting is data the read-only profiles drop.
    pub(super) data_only: bool,
}

/// The command with every inert environment prefix removed, or `None` when
/// there is nothing to remove or any prefix might change execution.
pub(super) fn project(command: &str) -> Option<String> {
    project_with(command, None, PathContext::default())
}

/// The command with its literal environment prefixes removed when at least
/// one of them is not inert but none can swap the program, its loader or its
/// credentials. `None` when [`project`] applies or nothing qualifies.
pub(super) fn project_reviewed(
    command: &str,
    context: PathContext<'_>,
) -> Option<ReviewedProjection> {
    let mut settings = reviewed::Reviewed::default();
    let command = project_with(command, Some(&mut settings), context)?;
    Some(ReviewedProjection {
        command,
        setting: settings.first?,
        data_only: settings.data_only,
    })
}

fn project_with(
    command: &str,
    mut setting: Option<&mut reviewed::Reviewed>,
    context: PathContext<'_>,
) -> Option<String> {
    if command.len() > MAX_PROJECTED_CHARS || command.contains(['\n', '\r', '\0']) {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let tokens = shell_tokens(&chars)?;
    let mut removed = vec![false; tokens.len()];
    let mut index = 0usize;
    let mut command_start = true;
    while index < tokens.len() {
        if tokens[index].is_control {
            command_start = COMMAND_SEPARATORS.contains(&tokens[index].value.as_str());
            index += 1;
            continue;
        }
        if !command_start {
            index += 1;
            continue;
        }
        command_start = false;
        index = strip_prefixes(
            &tokens,
            &chars,
            index,
            &mut removed,
            setting.as_deref_mut(),
            context,
        )?;
    }
    if !removed.contains(&true) {
        return None;
    }
    let mut projected = String::with_capacity(command.len());
    let mut cursor = 0usize;
    for (token, drop) in tokens.iter().zip(&removed) {
        if *drop {
            projected.extend(&chars[cursor..token.start]);
            cursor = next_word_start(&chars, token.end);
        }
    }
    projected.extend(&chars[cursor..]);
    let projected = projected.trim().to_owned();
    (!projected.is_empty() && projected != command.trim()).then_some(projected)
}

/// Mark leading assignments and `env` wrappers of one simple command and
/// return the index of its executable; `None` when a prefix is not inert.
fn strip_prefixes(
    tokens: &[ShellToken],
    chars: &[char],
    mut index: usize,
    removed: &mut [bool],
    mut setting: Option<&mut reviewed::Reviewed>,
    context: PathContext<'_>,
) -> Option<usize> {
    let mut stripped = false;
    let mut required = Vec::new();
    while index < tokens.len() && !tokens[index].is_control {
        let token = &tokens[index];
        if let Some((name, value)) = shell_assignment(chars, token) {
            let reviewed = setting.is_some();
            if !(literal_word(chars, token) || reviewed && private_temp_word(chars, token)) {
                return None;
            }
            if !inert_assignment(name, value) {
                search_path::review(setting.as_deref_mut(), &mut required, name, value, context)?;
            }
        } else if token.value == "env" || token.value == "/usr/bin/env" {
            removed[index] = true;
            index = strip_env_options(
                tokens,
                chars,
                index + 1,
                removed,
                setting.as_deref_mut(),
                &mut required,
                context,
            )?;
            stripped = true;
            continue;
        } else {
            break;
        }
        removed[index] = true;
        stripped = true;
        index += 1;
    }
    // A prefix with nothing after it sets shell state or dumps the
    // environment; leave that to the full parser.
    if stripped && (index >= tokens.len() || tokens[index].is_control) {
        return None;
    }
    // Guard's own launchers prove their exact invocation, environment
    // included; a prefix in front of them is never projected away.
    if stripped && guard_launcher(&tokens[index].value) {
        return None;
    }
    if !required.is_empty() && !search_path::admits(&required, &tokens[index].value) {
        return None;
    }
    Some(index)
}

fn guard_launcher(executable: &str) -> bool {
    executable
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name.to_ascii_lowercase().starts_with("hol-guard"))
}

/// Mark the `-u NAME` / `--unset=NAME` / `NAME=VALUE` arguments of an `env`
/// wrapper and return the index of the wrapped executable. Any other option
/// (`-i`, `-C`, `-S`, `-P`, ...) changes execution and is not inert.
fn strip_env_options(
    tokens: &[ShellToken],
    chars: &[char],
    mut index: usize,
    removed: &mut [bool],
    mut setting: Option<&mut reviewed::Reviewed>,
    required: &mut Vec<&'static [&'static str]>,
    context: PathContext<'_>,
) -> Option<usize> {
    while index < tokens.len() && !tokens[index].is_control {
        let token = &tokens[index];
        if !literal_word(chars, token) {
            return None;
        }
        let value = token.value.as_str();
        if value == "--" {
            removed[index] = true;
            index += 1;
            break;
        }
        if value == "-u" || value == "--unset" {
            let name = tokens.get(index + 1).filter(|next| !next.is_control)?;
            if !literal_word(chars, name) || !inert_unset(&name.value) {
                return None;
            }
            removed[index] = true;
            removed[index + 1] = true;
            index += 2;
            continue;
        }
        if let Some(name) = value
            .strip_prefix("--unset=")
            .or_else(|| value.strip_prefix("-u").filter(|rest| !rest.is_empty()))
        {
            if !inert_unset(name) {
                return None;
            }
        } else if value.starts_with('-') {
            return None;
        } else if let Some((name, assigned)) = assignment(token) {
            if !inert_assignment(name, assigned) {
                search_path::review(setting.as_deref_mut(), required, name, assigned, context)?;
            }
        } else {
            break;
        }
        removed[index] = true;
        index += 1;
    }
    Some(index)
}

fn assignment(token: &ShellToken) -> Option<(&str, &str)> {
    let (name, value) = token.value.split_once('=')?;
    let mut characters = name.chars();
    let first = characters.next()?;
    ((first == '_' || first.is_ascii_alphabetic())
        && characters.all(|value| value == '_' || value.is_ascii_alphanumeric()))
    .then_some((name, value))
}

/// A prefix word is an assignment only when its name and `=` are unquoted;
/// the shell runs `'LC_ALL=C' ls` as a program named `LC_ALL=C`.
fn shell_assignment<'t>(chars: &[char], token: &'t ShellToken) -> Option<(&'t str, &'t str)> {
    let (name, value) = assignment(token)?;
    let raw = chars.get(token.start..token.end)?;
    (raw.len() > name.len()
        && raw[name.len()] == '='
        && raw[..name.len()].iter().copied().eq(name.chars()))
    .then_some((name, value))
}

/// The raw word has no expansion, substitution, glob or escape.
fn literal_word(chars: &[char], token: &ShellToken) -> bool {
    literal_chars(&chars[token.start..token.end])
}

/// The raw word's only expansions are `$TMPDIR`, `${TMPDIR}` or
/// `${TMPDIR:-/tmp}` and nothing in the command rebinds `TMPDIR`. Only a
/// reviewed projection drops such a setting: the projection never settles
/// below review, and moving it to the workspace sandbox, which sets `TMPDIR`
/// itself, re-checks the raw command.
fn private_temp_word(chars: &[char], token: &ShellToken) -> bool {
    let word: String = chars[token.start..token.end].iter().collect();
    let command: String = chars.iter().collect();
    if !crate::pretool::workspace_contained::private_temp_expansions_only(&word)
        || crate::pretool::workspace_contained::rebinds_private_temp(&command)
    {
        return false;
    }
    let fallback = format!(
        "${}",
        crate::pretool::workspace_contained::PRIVATE_TEMP_WITH_FALLBACK
    );
    let rest: Vec<char> = word
        .replace(&fallback, "")
        .replace("${TMPDIR}", "")
        .replace("$TMPDIR", "")
        .chars()
        .collect();
    literal_chars(&rest)
}

fn literal_chars(word: &[char]) -> bool {
    !word.iter().any(|character| {
        matches!(
            character,
            '$' | '`'
                | '\\'
                | '('
                | ')'
                | '{'
                | '}'
                | '*'
                | '?'
                | '['
                | ']'
                | '~'
                | '<'
                | '>'
                | '!'
        )
    })
}

fn inert_assignment(name: &str, value: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if QUIETING_SETTINGS
        .iter()
        .any(|(known, quiet)| upper == *known && value == *quiet)
    {
        return true;
    }
    // Clearing a credential only removes authority from the command.
    if value.is_empty()
        && CREDENTIAL_MARKERS
            .iter()
            .any(|marker| upper.contains(marker))
    {
        return true;
    }
    if (upper.starts_with("LC_") || PRESENTATION_NAMES.contains(&upper.as_str()))
        && plain_scalar(value)
    {
        return true;
    }
    // Any program may read any other name, so other settings are reviewed
    // through the projection instead of passing as inert.
    false
}

fn plain_scalar(value: &str) -> bool {
    value.len() <= MAX_SCALAR_CHARS
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._:+,-".contains(character))
}

/// Unsetting removes context; only names whose absence changes which config
/// or executables a tool loads stay unproven.
/// Commit identity a caller may clear so Git falls back to its configured
/// author and committer; clearing one changes no program, path or config.
const GIT_IDENTITY_SETTINGS: &[&str] = &[
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
];

fn inert_unset(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if GIT_IDENTITY_SETTINGS.contains(&upper.as_str()) {
        return true;
    }
    assignment_name_shape(name)
        && !matches!(upper.as_str(), "PATH" | "HOME")
        && ![
            "XDG_", "GIT_", "GUARD_", "HOL_", "CLAUDE", "CODEX_", "ZCODE",
        ]
        .iter()
        .any(|prefix| upper.starts_with(prefix))
}

/// A setting that may change behavior but leaves the program, its loader and
/// its credentials alone, so a human can review the command it prefixes.
fn reviewable_assignment(name: &str, value: &str, context: PathContext<'_>) -> bool {
    let upper = name.to_ascii_uppercase();
    if upper == "NODE_PATH" {
        return trusted_node_path(value, context);
    }
    name.len() <= MAX_SETTING_CHARS
        && !UNREVIEWABLE_NAMES.contains(&upper.as_str())
        && !UNREVIEWABLE_PREFIXES
            .iter()
            .any(|prefix| upper.starts_with(prefix))
        && !upper.ends_with("PROXY")
        && !CREDENTIAL_MARKERS
            .iter()
            .any(|marker| upper.contains(marker))
        && !code_loading_name(&upper)
}

/// Whether `NAME=value` is a setting a one-time approval may bind by its
/// spelling: a reviewable name (the same test as above) with a short plain
/// value. A search path, a file or any text a program could parse as a
/// program stays outside, so the approved retry runs what was reviewed.
pub fn bindable_setting(name: &str, value: &str) -> bool {
    assignment_name_shape(name)
        && !name.eq_ignore_ascii_case("NODE_PATH")
        && reviewable_assignment(name, value, PathContext::default())
        && plain_scalar(value)
}

/// `NODE_PATH` as one canonical, existing `node_modules` directory inside the
/// working directory or home, with no hidden component, symlink or list
/// separator. Module lookup then falls back to a dependency tree the project
/// already trusts. The command still never settles below review.
fn trusted_node_path(value: &str, context: PathContext<'_>) -> bool {
    use std::path::{Component, Path};
    let path = Path::new(value);
    if value.len() > 1024
        || !path.is_absolute()
        || value.contains([':', ';', '\\'])
        || path.file_name().is_none_or(|name| name != "node_modules")
        || path.components().any(|component| match component {
            Component::Normal(name) => name.to_string_lossy().starts_with('.'),
            Component::RootDir | Component::Prefix(_) => false,
            _ => true,
        })
    {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(path) else {
        return false;
    };
    if canonical != path || !canonical.is_dir() {
        return false;
    }
    let inside = |root: Option<&str>| {
        root.and_then(|root| std::fs::canonicalize(root).ok())
            .is_some_and(|root| canonical.starts_with(root))
    };
    (inside(context.cwd) || inside(context.home_dir))
        && guard_secure_fs::sensitive_path_family(&canonical).is_none()
        && !guard_secure_fs::credential_named_path(&canonical)
}

fn code_loading_name(upper: &str) -> bool {
    crate::command_compatibility::code_or_redirect_environment_name(upper)
}

/// The first leading setting of any simple command that can load other code,
/// as a shape-checked name a reason may echo.
pub(super) fn code_loading_setting(command: &str) -> Option<String> {
    leading_setting(command, |upper| {
        crate::command_compatibility::code_or_redirect_environment_name(upper)
    })
}

/// The first leading setting of any simple command named for a credential
/// (`API_KEY`, `GH_TOKEN`), as a shape-checked name a reason may echo.
pub(super) fn credential_setting(command: &str) -> Option<String> {
    leading_setting(
        command,
        crate::command_compatibility::credential_routing_environment_name,
    )
}

/// The heap size when the first code-loading setting is `NODE_OPTIONS` and it
/// holds only `--max-old-space-size=<MiB>`. That option loads no code, and
/// `node --max-old-space-size=<MiB> <script>` is a form the read-only sandbox
/// accepts, so a reason may point the agent to it.
pub(super) fn node_heap_only_setting(command: &str) -> Option<String> {
    let (name, value) = leading_assignment(command, |upper| {
        crate::command_compatibility::code_or_redirect_environment_name(upper)
    })?;
    let size = value.strip_prefix("--max-old-space-size=")?;
    (name.eq_ignore_ascii_case("NODE_OPTIONS")
        && (1..=6).contains(&size.len())
        && size.bytes().all(|byte| byte.is_ascii_digit())
        && size
            .parse::<u32>()
            .is_ok_and(|mib| (16..=131072).contains(&mib)))
    .then(|| size.to_owned())
}

fn leading_setting(command: &str, matches: impl Fn(&str) -> bool) -> Option<String> {
    leading_assignment(command, matches).map(|(name, _)| name)
}

fn leading_assignment(command: &str, matches: impl Fn(&str) -> bool) -> Option<(String, String)> {
    if command.len() > MAX_PROJECTED_CHARS {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let tokens = shell_tokens(&chars)?;
    let mut command_start = true;
    let mut in_prefix = false;
    for token in &tokens {
        if token.is_control {
            command_start = COMMAND_SEPARATORS.contains(&token.value.as_str());
            in_prefix = false;
            continue;
        }
        if command_start {
            command_start = false;
            in_prefix = true;
        }
        if !in_prefix {
            continue;
        }
        if token.value == "env" || token.value == "/usr/bin/env" {
            continue;
        }
        let Some((name, value)) = shell_assignment(chars.as_slice(), token) else {
            in_prefix = false;
            continue;
        };
        if name.len() <= MAX_SETTING_CHARS
            && assignment_name_shape(name)
            && matches(&name.to_ascii_uppercase())
        {
            return Some((name.to_owned(), value.to_owned()));
        }
    }
    None
}

/// The first leading setting of any simple command whose value carries a
/// command substitution, backtick or variable expansion, as a shape-checked
/// name a reason may echo.
pub(super) fn substituted_setting(command: &str) -> Option<String> {
    if command.len() > MAX_PROJECTED_CHARS {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let tokens = shell_tokens(&chars)?;
    let mut command_start = true;
    let mut in_prefix = false;
    // Only a setting that a command follows reaches that command's
    // environment. A bare `n=$((n+1))` sets a shell variable.
    let mut pending: Option<String> = None;
    let mut bare_env = false;
    for token in &tokens {
        if token.is_control {
            // `env` with nothing after it still passes the setting on.
            if bare_env && pending.is_some() {
                return pending;
            }
            bare_env = false;
            command_start = COMMAND_SEPARATORS.contains(&token.value.as_str());
            in_prefix = false;
            pending = None;
            continue;
        }
        if command_start {
            command_start = false;
            in_prefix = true;
        }
        if !in_prefix || token.value == "env" || token.value == "/usr/bin/env" {
            bare_env = in_prefix;
            continue;
        }
        let Some((name, _)) = shell_assignment(chars.as_slice(), token) else {
            bare_env = false;
            if pending.is_some() {
                return pending;
            }
            in_prefix = false;
            continue;
        };
        let raw = chars.get(token.start..token.end)?;
        if pending.is_none()
            && name.len() <= MAX_SETTING_CHARS
            && assignment_name_shape(name)
            && raw.iter().any(|character| matches!(character, '$' | '`'))
        {
            pending = Some(name.to_owned());
        }
    }
    if bare_env {
        return pending;
    }
    None
}

fn assignment_name_shape(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && characters.all(|value| value == '_' || value.is_ascii_alphanumeric())
}

fn next_word_start(chars: &[char], mut index: usize) -> usize {
    while index < chars.len() && chars[index].is_whitespace() {
        index += 1;
    }
    index
}

#[cfg(test)]
#[path = "env_prefix_projection_tests.rs"]
mod tests;

/// Settings that only remove Git configuration sources. Isolating the global
/// and system files leaves a subset of the configuration the unexported
/// command sees, so a read proven helper-free without them stays helper-free.
const GIT_CONFIG_ISOLATION: [(&str, &str); 3] = [
    ("GIT_CONFIG_GLOBAL", "/dev/null"),
    ("GIT_CONFIG_SYSTEM", "/dev/null"),
    ("GIT_CONFIG_NOSYSTEM", "1"),
];

/// The command after leading `export NAME=value...;` statements that set only
/// [`GIT_CONFIG_ISOLATION`] values. The caller accepts the remainder's verdict
/// only when it allows, never to lower a review or block.
pub(super) fn project_git_config_isolation(command: &str) -> Option<String> {
    let mut rest = command.trim_start();
    let mut stripped = false;
    while let Some(after) = rest.strip_prefix("export ") {
        let end = after.find([';', '&', '\n', '|', '(', ')', '<', '>', '`', '$'])?;
        let (assignments, tail) = after.split_at(end);
        let tail = tail.strip_prefix(';').or_else(|| tail.strip_prefix("&&"))?;
        let mut count = 0;
        for token in assignments.split_whitespace() {
            let (name, value) = token.split_once('=')?;
            if !GIT_CONFIG_ISOLATION.contains(&(name, value)) {
                return None;
            }
            count += 1;
        }
        if count == 0 {
            return None;
        }
        stripped = true;
        rest = tail.trim_start();
    }
    (stripped && !rest.is_empty()).then(|| rest.to_owned())
}
