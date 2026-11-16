//! The directory a `git clone` or `git submodule add` creates when the step
//! names no destination of its own.
//!
//! Guard screens where a checkout lands, so a step that names only its
//! repository still has a destination: the one Git derives from that
//! repository. Reading it the way Git does keeps a remote whose last
//! component is a protected name — `…/LaunchAgents`, `…/.claude` — from
//! reaching that directory unscreened.

/// A URL or an SCP-style `host:path` remote, which Git never opens as a
/// local directory. A word with a `..` component is always screened as a
/// path: as a destination, `ab:/../../x` is a directory that climbs out.
pub(super) fn remote_word(word: &str) -> bool {
    if word.split(['/', '\\']).any(|part| part == "..") {
        return false;
    }
    if word.contains("://") {
        return true;
    }
    let Some((host, _)) = word.split_once(':') else {
        return false;
    };
    host.len() > 1 && !host.contains(['/', '\\']) && !host.starts_with(['.', '~'])
}

/// The directory `git clone <repository>` creates when none is given, the
/// way Git guesses it: trailing separators, whitespace and `/.git` dropped,
/// the scheme and any authentication skipped, a bare `host:port` reduced to
/// the host, the last component without `.git`, and runs of whitespace and
/// control characters collapsed to one space and trimmed. Git strips
/// `.bundle` only from a bundle file, so a name ending in it is screened in
/// both forms. `None` when nothing is left to name it.
pub(super) fn guessed_directories(repository: &str) -> Option<Vec<String>> {
    let separator = |c: char| c == '/' || c == '\\';
    let mut trimmed =
        repository.trim_end_matches(|c: char| separator(c) || c.is_ascii_whitespace());
    if let Some(parent) = trimmed
        .strip_suffix(".git")
        .and_then(|rest| rest.strip_suffix(separator))
        .filter(|parent| !parent.is_empty())
    {
        trimmed = parent.trim_end_matches(separator);
    }
    // Git reads the name past the scheme and past authentication, and only
    // then asks whether what is left is a bare host and port. Reading those
    // over the whole word names `https://hooks:443` after its port and
    // `ssh://git@LaunchAgents` after its user, so the directory Git would
    // create goes unscreened.
    trimmed = &trimmed[trimmed.find("://").map_or(0, |at| at + 3)..];
    // Authentication is stripped greedily, up to the last `@` before the
    // first separator.
    let mut authentication = None;
    for (at, character) in trimmed.char_indices() {
        if separator(character) {
            break;
        }
        if character == '@' {
            authentication = Some(at + character.len_utf8());
        }
    }
    if let Some(at) = authentication {
        trimmed = &trimmed[at..];
    }
    if !trimmed.contains('/') {
        if let Some((host, port)) = trimmed.rsplit_once(':') {
            if port.bytes().all(|byte| byte.is_ascii_digit()) {
                trimmed = host;
            }
        }
    }
    let name = trimmed.rsplit(|c: char| separator(c) || c == ':').next()?;
    let mut names = vec![name.strip_suffix(".git").unwrap_or(name)];
    names.extend(name.strip_suffix(".bundle"));
    let names: Vec<String> = names
        .into_iter()
        .map(|name| {
            name.split(|c: char| c.is_ascii_whitespace() || c.is_ascii_control())
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    (!names.iter().any(String::is_empty)).then_some(names)
}
