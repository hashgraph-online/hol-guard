//! Agents routinely prefix a command with inert environment settings
//! (`LC_ALL=C ls`, `env -u GH_TOKEN gh api ...`, `GH_TOKEN= gh repo view`).
//! The canonical parser treats any prefix as unmodeled context, which made
//! the whole command fail closed. This projection removes only prefixes that
//! cannot change how the remaining command runs, so the remaining command is
//! judged on its own merits. Any prefix that can redirect execution, config,
//! credentials, code loading or network routing leaves the command untouched.

use crate::cloud_scrub_shell::{shell_tokens, ShellToken};
use crate::pretool::PathContext;

#[path = "env_prefix_leading.rs"]
mod leading;
#[path = "env_prefix_reviewed.rs"]
mod reviewed;
#[path = "env_prefix_search_path.rs"]
mod search_path;
#[path = "env_prefix_settings.rs"]
mod settings;
#[path = "env_prefix_values.rs"]
mod values;
#[path = "env_prefix_words.rs"]
mod words;
pub(super) use leading::{code_loading_setting, credential_setting, substituted_setting};
pub(super) use reviewed::join_reviewed;
pub use settings::bindable_setting;
use settings::{inert_assignment, inert_unset, ordinary_project_setting};
pub(super) use values::removes_values;
use words::{
    assignment, literal_assignment_word, literal_word, private_temp_word, quoted_assignment_word,
    shell_assignment,
};

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
    // A bare `exec` hands the shell's process to the command that follows, so
    // the program the rest of the words run, and the arguments it runs with,
    // are the ones the bare spelling runs. Read past it so a setting behind it
    // is projected the way the bare spelling's is; without this the loop below
    // stops at the first word and `exec env -u NODE_OPTIONS npm test` carries
    // a floor that `env -u NODE_OPTIONS npm test` does not. `exec -c` runs
    // with an empty environment and `exec -a` renames the program, so only the
    // option-less spelling is transparent.
    //
    // Only an `env` wrapper may follow. A shell recognizes an assignment word
    // only in front of the command word, and here `exec` is that word, so the
    // `LC_ALL=C` of `exec LC_ALL=C ls src` is the program `exec` is asked to
    // run, not a setting in front of `ls`. Reading past `exec` there would
    // strip the word the shell actually executes and hand the reviewer a
    // command the caller never wrote.
    let launcher = (tokens[index].value == "exec"
        && literal_word(chars, &tokens[index])
        && index + 1 < tokens.len()
        && !tokens[index + 1].is_control
        && matches!(tokens[index + 1].value.as_str(), "env" | "/usr/bin/env"))
    .then(|| {
        let at = index;
        index += 1;
        at
    });
    while index < tokens.len() && !tokens[index].is_control {
        let token = &tokens[index];
        if let Some((name, value)) = shell_assignment(chars, token) {
            let reviewed = setting.is_some();
            if !(literal_assignment_word(chars, token, name)
                || reviewed && private_temp_word(chars, token))
            {
                return None;
            }
            if !(inert_assignment(name, value)
                || !reviewed && ordinary_project_setting(name, value))
            {
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
    // The launcher only leaves the text when a setting behind it did. On its
    // own it is the command the caller wrote, and nothing here has read it.
    if let (Some(at), true) = (launcher, stripped) {
        removed[at] = true;
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
        let literal = match assignment(token) {
            Some((name, _)) => quoted_assignment_word(chars, token, name),
            None => literal_word(chars, token),
        };
        if !literal {
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
            if !(inert_assignment(name, assigned)
                || setting.is_none() && ordinary_project_setting(name, assigned))
            {
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
