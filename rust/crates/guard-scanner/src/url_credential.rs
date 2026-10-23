//! A URL's password slot that holds no password.
//!
//! `scheme://user:password@host` puts a real credential in front of an agent
//! when `git remote -v`, `.git/config` or a sync script prints it. Templates
//! and docs fill the same slot with a substitution (`${TOKEN}`, `{password}`,
//! `%s`), a mask (`***`) or the slot's own name (`user:password@`), and none of
//! those reveal anything.

use crate::masked_value;
use regex::Regex;
use std::sync::OnceLock;

/// Words that fill the slot in docs and templates. Only a whole password
/// counts, so `test-Kq7…` is still a credential.
const SLOT_NAMES: &[&str] = &[
    "password",
    "passwd",
    "pass",
    "pwd",
    "pw",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "example",
    "sample",
    "placeholder",
    "fake",
    "dummy",
    "invalid",
    "test",
];

static BRACED: OnceLock<Regex> = OnceLock::new();
static SUBSTITUTION: OnceLock<Regex> = OnceLock::new();

/// `${NAME}` or `${NAME:-word}`, capturing the operator and the word. The
/// word may itself be one `${OTHER}`.
fn braced_regex() -> &'static Regex {
    BRACED.get_or_init(|| {
        Regex::new(
            r"^\$\{[A-Za-z_][A-Za-z0-9_]*(?::?([-=+?])(\$\{[A-Za-z_][A-Za-z0-9_]*\}|[^}]*))?\}$",
        )
        .expect("URL braced substitution rule must compile")
    })
}

/// A whole password that is another template slot: `$TOKEN`, `$(cmd)`,
/// `{password}`, `%s` or `%(password)s`. A bare `$name` counts only in one
/// case, as variables are written, so a real password such as `$Kq7…` or a
/// percent-encoded `%40…` is not a stand-in.
fn substitution_regex() -> &'static Regex {
    SUBSTITUTION.get_or_init(|| {
        Regex::new(
            r"^(?:\$(?:[A-Z_][A-Z0-9_]*|[a-z_][a-z0-9_]*)|\$\([^)]*\)|\{[A-Za-z_][A-Za-z0-9_.]*\}|%(?:\([A-Za-z_][A-Za-z0-9_]*\))?s)$",
        )
        .expect("URL substitution rule must compile")
    })
}

/// Whether a URL password is a stand-in rather than a credential.
pub(crate) fn is_placeholder(password: &str) -> bool {
    if let Some(captures) = braced_regex().captures(password) {
        // `${NAME:?word}` only uses `word` as an error message, but
        // `${PASSWORD:-Kq7…}` still prints its literal fallback.
        if captures
            .get(1)
            .is_some_and(|operator| operator.as_str() == "?")
        {
            return true;
        }
        return captures
            .get(2)
            .is_none_or(|word| word.as_str().is_empty() || is_placeholder(word.as_str()));
    }
    substitution_regex().is_match(password)
        || password
            .chars()
            .all(|character| matches!(character, '*' | '•' | '●' | 'x' | 'X'))
        || masked_value::is_masked(password)
        || SLOT_NAMES
            .iter()
            .any(|name| password.eq_ignore_ascii_case(name))
}

/// The password slot of a `url-credential` match.
pub(crate) fn password(matched: &str) -> Option<&str> {
    let (_, rest) = matched.split_once("://")?;
    let userinfo = &rest[..rest.rfind('@')?];
    let (_, password) = userinfo.split_once(':')?;
    Some(password)
}

#[cfg(test)]
mod tests {
    use crate::scan_text;
    use guard_rules::MAX_SCAN_BYTES;

    fn url_credential(text: &str) -> bool {
        scan_text(text, true, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "url-credential")
    }

    fn password() -> String {
        ["Kq7Xr2", "mWp9Lq4z"].concat()
    }

    #[test]
    fn a_password_in_a_url_is_a_credential() {
        let password = password();
        for text in [
            format!("origin\thttps://alice:{password}@git.lan/alice/notes.git (push)"),
            format!("\turl = https://alice:{password}@git.lan/alice/notes.git"),
            format!("DATABASE_URL=postgres://app:{password}@db.lan:5432/app"),
            format!("sync.sh:12:git push https://alice:{password}@git.lan/alice/notes.git"),
            format!("redis://:{password}@cache.lan:6379/0"),
            format!("https://alice:{password}@例え.テスト/notes.git"),
        ] {
            assert!(url_credential(&text), "{text:?}");
        }
    }

    #[test]
    fn a_password_that_only_looks_like_a_stand_in_is_a_credential() {
        let password = password();
        for text in [
            format!("https://alice:%40{password}@git.lan/alice/notes.git"),
            format!("https://alice:${password}@git.lan/alice/notes.git"),
            format!("https://alice:{{{password}@git.lan/alice/notes.git"),
            format!("https://alice:it's{password}@git.lan/alice/notes.git"),
            format!("https://test:{password}@git.lan/alice/notes.git"),
            format!("https://alice:{password}@example.com/notes.git"),
            format!("https://alice:test-{password}@prod.lan/notes.git"),
            format!("https://alice:${{PASSWORD:-{password}}}@git.lan/alice/notes.git"),
        ] {
            assert!(url_credential(&text), "{text:?}");
            assert!(
                scan_text(&text, false, false, MAX_SCAN_BYTES, None)
                    .matches
                    .iter()
                    .any(|matched| matched.classifier == "url-credential"),
                "{text:?}"
            );
        }
    }

    #[test]
    fn a_url_without_a_password_is_not_a_credential() {
        for text in [
            "git@github.com:org/repo.git",
            "ssh://git@git.lan:22/alice/notes.git",
            "https://alice@git.lan/alice/notes.git",
            "http://[::1]:8080/health",
            "http://localhost:8080/path?next=a@b",
            "https://user:@git.lan/repo.git",
        ] {
            assert!(!url_credential(text), "{text:?}");
        }
    }

    #[test]
    fn a_stand_in_password_is_not_a_credential() {
        for text in [
            "https://alice:${GITEA_TOKEN}@git.lan/alice/notes.git",
            "https://alice:$GITEA_TOKEN@git.lan/alice/notes.git",
            "https://alice:${GITEA_TOKEN:-}@git.lan/alice/notes.git",
            "https://alice:${GITEA_TOKEN:-$FALLBACK_TOKEN}@git.lan/alice/notes.git",
            "git push https://ci:${CI_TOKEN:?required}@git.lan/repo.git",
            "https://alice:${GITEA_TOKEN:-${FALLBACK_TOKEN}}@git.lan/alice/notes.git",
            "git push https://ci:${CI_TOKEN?required}@git.lan/repo.git",
            "https://alice:test@git.lan/alice/notes.git",
            "https://alice:%(token)s@git.lan/alice/notes.git",
            "f\"postgres://{user}:{password}@{host}/app\"",
            "\"https://%s:%s@%s\" % (user, token, host)",
            "https://alice:***@git.lan/alice/notes.git",
            "https://alice:xxxxxxxx@git.lan/alice/notes.git",
            "https://username:password@git.lan/repo.git",
            "https://oauth2:TOKEN@gitlab.lan/group/repo.git",
            "https://<user>:<token>@git.lan/repo.git",
        ] {
            assert!(!url_credential(text), "{text:?}");
        }
    }
}
