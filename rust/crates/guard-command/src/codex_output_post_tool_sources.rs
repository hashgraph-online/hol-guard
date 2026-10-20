//! Local secret sources a post-tool command references: path-looking tokens
//! in the text, shell words and URL-shaped tokens that name an existing local
//! file (`commands_support_codex_tool_output.py`), plus the local-content
//! review and the source label the artifact reports.

use std::path::Path;

use crate::cloud_audit_sync::{urlparse_path_end, urlsplit};
use crate::codex_output_commands::{may_read_local_content_tail, reads_environment_pipeline};
use crate::codex_output_entry::{contextual_segments, scope_of};
use crate::codex_output_fs as pyfs;
use crate::codex_output_post_tool::{absolute, model, PostToolError, Run};
use crate::codex_output_py::{is_py_space, py_strip, shlex_split, PyPath};
use crate::shell_secret_read_support::{classify_request_secret_path, SecretPathMatch};

const SEPARATORS: &str = " \t\r\n'\"`<>|;(){}[]";

/// The parse error Python's `urllib.parse.urlparse` raises propagates.
const URL_INVALID: PostToolError = "native_codex_post_tool_url_invalid";

/// `classify_secret_path(token, cwd=cwd)`: the home is always `Path.home()`.
fn classify(run: &Run, token: &str, cwd: Option<&PyPath>) -> Option<SecretPathMatch> {
    let cwd = cwd.map(PyPath::to_string);
    let home = run.ctx.default_home.to_string();
    classify_request_secret_path(token, cwd.as_deref().map(Path::new), Some(Path::new(&home)))
}

/// `urlparse(token)`: scheme, netloc and the path without the final `;params`.
fn urlparse(token: &str) -> Result<(String, String, String), PostToolError> {
    let mut parts = urlsplit(token).map_err(|_| URL_INVALID)?;
    let end = urlparse_path_end(&parts);
    parts.path.truncate(end);
    Ok((parts.scheme, parts.netloc, parts.path))
}

/// `_codex_token_is_url`.
fn token_is_url(token: &str) -> Result<bool, PostToolError> {
    let (scheme, netloc, _) = urlparse(token)?;
    Ok(!scheme.is_empty() && !netloc.is_empty())
}

/// `_codex_existing_local_path_match`.
fn existing_local_path_match(
    run: &Run,
    token: &str,
    cwd: Option<&PyPath>,
) -> Result<Option<SecretPathMatch>, PostToolError> {
    let Some(cwd) = cwd else {
        return Ok(None);
    };
    let base_dir = absolute(run.ctx, cwd);
    let base_dir = pyfs::resolve(&base_dir).ok_or(URL_INVALID)?;
    let (scheme, netloc, path) = urlparse(token)?;
    if scheme.is_empty() || netloc.is_empty() {
        return Ok(None);
    }
    let mut relative = vec![format!("{scheme}:"), netloc];
    for part in PyPath::new(&path).parts() {
        if !matches!(part.as_str(), "" | "/" | "." | "..") {
            relative.push(part);
        }
    }
    if relative.len() <= 2 && path.trim_matches('/').is_empty() {
        return Ok(None);
    }
    let mut candidate = base_dir.clone();
    for part in &relative {
        candidate = candidate.join(part);
    }
    if pyfs::exists(&candidate) != Ok(true) {
        return Ok(None);
    }
    let parts = candidate.relative_to(&base_dir).ok_or(URL_INVALID)?;
    let relative_candidate = PyPath::new(&parts.join("/"));
    Ok(classify(run, &relative_candidate.to_string(), Some(cwd)))
}

fn is_separator(c: char) -> bool {
    SEPARATORS.contains(c)
}

/// `str.isalpha()` / `str.isalnum()` for one character.
fn py_alpha(c: char) -> bool {
    c.is_alphabetic()
}

/// `_codex_path_token_is_url_path`: the token prefix before `start` is a URL.
fn path_token_is_url_path(chars: &[char], start: usize) -> bool {
    let prefix: String = chars[..start].iter().collect::<String>().to_lowercase();
    let prefix: Vec<char> = prefix.chars().collect();
    let last = prefix.iter().rposition(|c| is_separator(*c));
    let token_prefix: String = prefix[last.map_or(0, |index| index + 1)..].iter().collect();
    if token_prefix.contains("://") {
        return true;
    }
    let scheme = token_prefix
        .strip_suffix(":/")
        .or_else(|| token_prefix.strip_suffix(':'))
        .unwrap_or("");
    scheme.chars().next().is_some_and(py_alpha)
        && scheme
            .chars()
            .all(|c| c.is_alphanumeric() || "+.-".contains(c))
}

fn word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn path_class(c: char) -> bool {
    !is_py_space(c) && !"'\"`<>|;(){}[]".contains(c)
}

/// One path-shaped token starting at `index`: where it ends, if one does.
fn path_token_at(chars: &[char], index: usize) -> Option<usize> {
    let at = |offset: usize| chars.get(index + offset).copied();
    let previous_ok = index == 0 || {
        let previous = chars[index - 1];
        !(word_char(previous) || "/.-".contains(previous))
    };
    if previous_ok && at(0) == Some('.') && at(1).is_some_and(|c| c.is_ascii_alphanumeric()) {
        let mut end = index + 2;
        while end < chars.len()
            && end - index - 2 < 255
            && (chars[end].is_ascii_alphanumeric() || "_.-".contains(chars[end]))
        {
            end += 1;
        }
        return Some(end);
    }
    let lead = match at(0)? {
        '~' | '/' => 1,
        '.' if at(1) == Some('.') => 2,
        '.' => 1,
        _ => return None,
    };
    let mut end = index + lead;
    while end < chars.len() && end - index - lead < 255 && path_class(chars[end]) {
        end += 1;
    }
    Some(end)
}

/// Every path-shaped token in `chars`, each with the offset it starts at.
fn path_tokens(chars: &[char]) -> Vec<(usize, String)> {
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        match path_token_at(chars, index) {
            Some(end) => {
                tokens.push((index, chars[index..end].iter().collect()));
                index = end;
            }
            None => index += 1,
        }
    }
    tokens
}

/// `_codex_url_like_local_path_tokens`.
fn url_like_local_path_tokens(chars: &[char]) -> Result<Vec<String>, PostToolError> {
    let mut tokens = Vec::new();
    let mut start = 0;
    for index in 0..=chars.len() {
        if index < chars.len() && !is_separator(chars[index]) {
            continue;
        }
        let token = &chars[start..index];
        start = index + 1;
        if !token.is_empty() && token.len() <= 255 {
            let token: String = token.iter().collect();
            if token_is_url(&token)? {
                tokens.push(token);
            }
        }
    }
    Ok(tokens)
}

/// `_codex_sensitive_path_matches_in_text`.
fn path_matches_in_text(
    run: &Run,
    text: &str,
    cwd: Option<&PyPath>,
) -> Result<Vec<SecretPathMatch>, PostToolError> {
    run.check()?;
    let chars: Vec<char> = text.chars().collect();
    let mut matches = Vec::new();
    for (start, token) in path_tokens(&chars) {
        let found = if path_token_is_url_path(&chars, start) {
            existing_local_path_match(run, &token, cwd)?
        } else {
            classify(run, &token, cwd)
        };
        matches.extend(found);
    }
    for token in url_like_local_path_tokens(&chars)? {
        matches.extend(existing_local_path_match(run, &token, cwd)?);
    }
    Ok(matches)
}

/// `_dedupe_codex_secret_path_matches`.
fn dedupe(matches: Vec<SecretPathMatch>) -> Vec<SecretPathMatch> {
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut deduped = Vec::new();
    for found in matches {
        let path = if found.requested_path.is_empty() {
            &found.path
        } else {
            &found.requested_path
        };
        let key = (found.family.clone(), path.clone());
        if !seen.contains(&key) {
            seen.push(key);
            deduped.push(found);
        }
    }
    deduped
}

/// `_codex_sensitive_local_source_matches`.
pub(crate) fn sensitive_local_source_matches(
    run: &Run,
    command: &str,
    cwd: Option<&PyPath>,
    applied: bool,
) -> Result<Vec<SecretPathMatch>, PostToolError> {
    if !applied {
        let context = model(run, command, cwd)?;
        if context.directory_change_present {
            let Ok(segments) = contextual_segments(&context) else {
                return Ok(Vec::new());
            };
            let mut matches = Vec::new();
            for (_, text, segment_cwd) in &segments {
                matches.extend(sensitive_local_source_matches(
                    run,
                    text,
                    Some(segment_cwd),
                    true,
                )?);
            }
            return Ok(dedupe(matches));
        }
    }
    let mut matches = path_matches_in_text(run, command, cwd)?;
    let Some(parts) = shlex_split(command) else {
        return Ok(matches);
    };
    for part in parts {
        let stripped = py_strip(&part);
        if stripped.is_empty() || stripped.starts_with('-') {
            continue;
        }
        if token_is_url(stripped)? {
            matches.extend(existing_local_path_match(run, stripped, cwd)?);
            continue;
        }
        matches.extend(classify(run, stripped, cwd));
    }
    Ok(dedupe(matches))
}

/// `_codex_command_may_read_local_content`.
pub(crate) fn may_read_local_content(
    run: &Run,
    command: &str,
    cwd: Option<&PyPath>,
) -> Result<bool, PostToolError> {
    let context = model(run, command, cwd)?;
    if context.directory_change_present {
        let Ok(segments) = contextual_segments(&context) else {
            return Ok(true);
        };
        for (_, text, segment_cwd) in &segments {
            if may_read_local_content(run, text, Some(segment_cwd))? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if !sensitive_local_source_matches(run, command, cwd, false)?.is_empty() {
        return Ok(true);
    }
    Ok(may_read_local_content_tail(
        command,
        scope_of(run.ctx, cwd, None),
    ))
}

/// `_codex_local_secret_source_label`.
pub(crate) fn local_secret_source_label(
    matches: &[SecretPathMatch],
    command: &str,
) -> Option<String> {
    let mut families: Vec<&str> = Vec::new();
    for found in matches {
        if !families.contains(&found.family.as_str()) {
            families.push(&found.family);
        }
    }
    match families.as_slice() {
        [only] => Some((*only).to_owned()),
        [first, ..] => Some(format!("{first} and other local secret files")),
        [] => reads_environment_pipeline(command).then(|| "environment variables".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{path_token_is_url_path, path_tokens};

    fn tokens(text: &str) -> Vec<String> {
        let chars: Vec<char> = text.chars().collect();
        path_tokens(&chars)
            .into_iter()
            .map(|(_, token)| token)
            .collect()
    }

    #[test]
    fn path_tokens_follow_the_python_pattern() {
        assert_eq!(tokens("cat .env ~/x ../a/b"), [".env", "~/x", "../a/b"]);
        assert_eq!(tokens("a.env x/.npmrc"), [".env", "/.npmrc"]);
        assert_eq!(tokens("echo 'q' (/etc/passwd)"), ["/etc/passwd"]);
    }

    #[test]
    fn url_prefixes_are_recognised() {
        let chars: Vec<char> = "curl file:///etc/x".chars().collect();
        assert!(path_token_is_url_path(&chars, 10));
        let chars: Vec<char> = "cat ./x".chars().collect();
        assert!(!path_token_is_url_path(&chars, 4));
    }
}
