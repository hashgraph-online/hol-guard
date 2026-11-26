//! What the shell the command starts in settles before the list runs: a
//! leading `cd` that cannot fail, and the home a leading `~` names.

use super::{names_variable, word_text, Binding, PathContext, MAX_VALUE_CHARS};
use std::collections::HashMap;

/// Whether the list's first command is a `cd` that cannot fail: one operand
/// naming a directory that exists, lies where a read may go and can be
/// searched, so the shell enters it and runs what follows its `&&`.
pub(super) fn enters(
    chars: &[char],
    words: &[(usize, usize)],
    bindings: &HashMap<String, Binding>,
    context: Option<PathContext<'_>>,
) -> bool {
    let (Some(context), [command, target]) = (context, words) else {
        return false;
    };
    let raw: String = chars[target.0..target.1].iter().collect();
    if word_text(chars, *command, bindings).as_deref() != Some("cd")
        || raw.contains(['$', '\\', '\'', '"', '`'])
    {
        return false;
    }
    crate::pretool::directory_targets::verified_cwd_target(&raw, context)
        .or_else(|| crate::pretool::directory_targets::verified_climb_target(&raw, context))
        // Entering needs search permission, which a stat through the
        // directory proves.
        .is_some_and(|directory| {
            std::fs::metadata(std::path::Path::new(&directory).join(".")).is_ok()
        })
}

/// The value of an assignment written `~` or `~/rest`, given the `rest` after
/// the tilde: the declared home joined with it. `None` for `~name`, for an
/// unknown home and for any value the shell would not pass through unchanged.
pub(super) fn home_value(rest: &[char], home: Option<&str>) -> Option<String> {
    let rest: String = rest.iter().collect();
    home.filter(|_| rest.is_empty() || rest.starts_with('/'))
        .map(|home| format!("{}{rest}", home.trim_end_matches('/')))
        .filter(|value| !value.is_empty() && value.chars().count() <= MAX_VALUE_CHARS)
        .filter(|value| literal(value))
}

/// The declared home a leading `~` in an assignment names. The shell expands
/// it there, so `f=~/x` holds the home path; it is written in place as that
/// path, never as a `~` a quoted use would keep. Only when the shell's HOME
/// is the declared home, a plain absolute literal, and nothing in the command
/// names `HOME`, so no step could have changed it. `~user`, a quoted tilde
/// and a tilde anywhere else keep the value unknown.
pub(super) fn declared_home<'a>(
    command: &str,
    context: Option<PathContext<'a>>,
) -> Option<&'a str> {
    context
        .filter(|context| context.shell_home_matches && !cfg!(windows))
        .and_then(|context| context.home_dir)
        .filter(|home| home.starts_with('/') && literal(home))
        .filter(|_| !names_variable(command, |name| name == "HOME"))
}

/// Text the shell passes through unchanged wherever it stands in a word.
pub(super) fn literal(value: &str) -> bool {
    value.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, '_' | '.' | '/' | '@' | '%' | '+' | ':' | ',' | '-')
    })
}
