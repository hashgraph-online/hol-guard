//! Credentials a command line carries as a word of its own.
//!
//! A shell hands a program its credential as an argument, not as an
//! assignment. `curl -H "Authorization: Bearer <token>"` writes the name and
//! the value either side of a scheme word, and `mysql --password <value>`
//! writes them either side of nothing but a space. Neither shape has the `=`
//! or the `:` directly between name and value that the contextual assignment
//! rule looks for, so a scan read `Bearer` as the whole value of
//! `Authorization` -- six characters, under the rule's own floor -- and read
//! `--password <value>` as two unrelated words. A deploy script, a CI job and
//! a `Dockerfile` are where credentials are written this way, and they are
//! ordinary files in a repository.
//!
//! The asymmetry was visible inside Guard already: the screen over tool output
//! in `lib.rs` has carried a `generic-bearer-token` pattern all along, so the
//! same bytes were named when an agent read them back and missed when they sat
//! in a committed file.
//!
//! Every shape this pass reads names itself. The header is `Authorization` or
//! `Proxy-Authorization` followed by a scheme that says what the value is, and
//! the option is a long flag whose own name is the word `password`, `token`,
//! `secret` or `key`. That is deliberate rather than incidental: the value has
//! no provider format to vouch for it, so the name beside it is the whole of
//! the evidence, and contextual scoring reads that name off the line. A flag
//! that does not say what it carries -- `curl -u user:pass` is the common one
//! -- has no such evidence and is left alone rather than guessed at.
//!
//! Two neighbouring shapes are deliberately out of scope. `--password=value`
//! already is an assignment and the assignment rule reports it. `Authorization:
//! Basic <payload>` carries `user:password` base64-encoded, and what reads a
//! payload is the encoded pass, which applies provider formats only; a
//! contextual credential inside one has no line of the file to be scored
//! against, so Basic stays unread here rather than being read without evidence.
//!
//! The value is held to the same bar as any other contextual credential:
//! the shared plausibility and indirect-reference guards decide it, so
//! `--token $GITHUB_TOKEN` is a reference rather than a secret and a value
//! carrying a path separator is not read as one. A credential a provider
//! format already named is not reported twice; the caller passes in what it
//! has already claimed.

use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

use super::{
    candidate_digest, candidate_is_indirect_reference, finding_from_match,
    generic_candidate_is_plausible, CandidateDigest, LineIndex, RuleMeta, SecretFinding,
};

/// Named among a finding's reasons when the credential stood in an
/// `Authorization` header.
pub const AUTHORIZATION_HEADER_REASON: &str = "authorization-header";

/// Named among a finding's reasons when the credential was the value of a
/// command-line option.
pub const CREDENTIAL_OPTION_REASON: &str = "credential-command-option";

/// Folded into `detector_version`, so a stored scan taken before this pass
/// existed is recognisable as one that never read a command line.
pub(super) const SHELL_CREDENTIAL_POLICY_VERSION: &str = "shell-credential-scan-v1";

/// The synthetic rule this pass reports under.
pub(super) const SHELL_RULE_META: RuleMeta = RuleMeta {
    rule_id: "credential-command",
    family: "Contextual credential on a command line",
    severity: "high",
    validation: "none",
    strong_format: false,
};

/// What the catalog says about that rule.
pub(super) const SHELL_RULE_DESCRIPTION: &str =
    "Credential written as an authorization header or as the value of a credential-naming option.";

/// `Authorization: <scheme> <credential>`, as a header line, a `curl -H`
/// argument or a quoted JSON field. The quote either side of the name is
/// optional because all three spellings occur, and the value's alphabet stops
/// it at the closing quote. Name, scheme and value share one physical line:
/// a scheme word that ends a line introduces nothing.
///
/// Only schemes whose own word says what the value is are read. `Basic` is
/// not one of them: its value is an encoding rather than a credential.
static AUTHORIZATION_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(AUTHORIZATION_HEADER_SOURCE).expect("AUTHORIZATION_HEADER is a static literal")
});

const AUTHORIZATION_HEADER_SOURCE: &str = concat!(
    r#"(?i)\b(?:proxy-)?authorization["']?[^\S\r\n]*:[^\S\r\n]*["']?"#,
    r"(?:bearer|token|apikey|api-key)[^\S\r\n]+",
    r"(?P<secret>[A-Za-z0-9+/=._~-]{12,512})",
);

/// A long option whose name says it carries a credential, with its value as
/// the next word.
///
/// The space after the name is what keeps `--password-stdin`,
/// `--password-file` and `--token-file` out: each names a source for the
/// credential rather than the credential, and the character after the name is
/// a hyphen rather than a space.
///
/// A quoted value runs to the quote that closes it, so the `;` or `|` a
/// password is free to contain stays inside the credential. It is still one
/// word: a quoted sentence is prose rather than a password. An unquoted value
/// stops at that same character, because there the shell stops the command
/// too and a redirection or a pipe is not part of the value. A value whose
/// opening quote never closes on the line is not read at all rather than read
/// as far as the line happens to go: half a password reported is half a
/// password redacted.
///
/// The space either side of the value is horizontal. A flag that ends its
/// line carries no credential, and the text beginning the line below belongs
/// to another command.
static CREDENTIAL_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(CREDENTIAL_OPTION_SOURCE).expect("CREDENTIAL_OPTION is a static literal")
});

const CREDENTIAL_OPTION_SOURCE: &str = concat!(
    r#"(?i)(?:^|[\s'"(])--"#,
    r"(?:admin-password|registry-password|client-secret|signing-secret|webhook-secret",
    r"|session-token|refresh-token|access-token|private-token|auth-token|api-token",
    r"|secret-key|access-key|api-key|password|passwd|apikey|token|secret)",
    r"[^\S\r\n]+",
    r#"(?:"(?P<double>[^\s"'`$\\]{12,256})""#,
    r#"|'(?P<single>[^\s"'`$\\]{12,256})'"#,
    r#"|(?P<secret>[^\s"'`,;|&<>()$\\]{12,256}))"#,
);

/// The credentials the command lines in `text` carry.
///
/// `claimed` holds the digests of the candidates already reported, so a token
/// a provider format or the assignment rule named is not named a second time
/// under this rule.
pub(super) fn shell_credential_findings(
    text: &str,
    path: &str,
    source: &str,
    commit: Option<&str>,
    lines: &LineIndex,
    claimed: &HashSet<CandidateDigest>,
    remaining: usize,
) -> Vec<SecretFinding> {
    let mut findings: Vec<SecretFinding> = Vec::new();
    if remaining == 0 {
        return findings;
    }
    // The same value can be written twice on one line, and a header and an
    // option can carry it between them. Counting either spelling a second
    // time would spend the caller's budget on a finding it goes on to drop,
    // leaving a later, different credential on the line unread.
    let mut read: HashSet<CandidateDigest> = HashSet::new();
    for (pattern, reason) in [
        (&*AUTHORIZATION_HEADER, AUTHORIZATION_HEADER_REASON),
        (&*CREDENTIAL_OPTION, CREDENTIAL_OPTION_REASON),
    ] {
        for captures in pattern.captures_iter(text) {
            // A quoted value is held whole by the quote that closes it, so
            // the shell metacharacter a password may contain stays inside the
            // credential rather than cutting it short.
            let (matched, quoted) = captures
                .name("secret")
                .map(|secret| (secret, false))
                .or_else(|| captures.name("double").map(|held| (held, true)))
                .or_else(|| captures.name("single").map(|held| (held, true)))
                .expect("one of the credential groups always matches");
            let candidate = matched.as_str();
            // A value spelled as a long option is the next flag on the line.
            // `--password --registry-password` names two options and hands
            // over no credential at all.
            if candidate.starts_with("--") {
                continue;
            }
            let digest = candidate_digest(candidate);
            if claimed.contains(&digest) {
                continue;
            }
            if !read.insert(digest) {
                continue;
            }
            // Quoting decides how the value reads. A bare word sits in the
            // command's own syntax, so a bracket or a `;` in it is shell
            // rather than credential; a quoted word was handed over whole by
            // the quotes around it, and the same characters are then part of
            // the password itself.
            if candidate_is_indirect_reference(candidate, quoted, path) {
                continue;
            }
            let whole_match = captures.get(0).expect("whole match always present");
            if !generic_candidate_is_plausible(candidate, quoted, path, whole_match.as_str()) {
                continue;
            }
            // Anchored on the credential rather than on the whole match. The
            // option arm consumes the whitespace that proves `--` starts a
            // word, and when that whitespace is the newline ending the line
            // above, the match begins one line too early.
            let finding = finding_from_match(
                &SHELL_RULE_META,
                candidate,
                text,
                matched.start(),
                path,
                source,
                commit,
                None,
                lines,
            );
            let Some(mut finding) = finding else { continue };
            finding.context_reasons.push(reason);
            findings.push(finding);
            if findings.len() >= remaining {
                return findings;
            }
        }
    }
    findings
}

/// The material this pass contributes to `detector_version`.
pub(super) fn shell_credential_material_line() -> String {
    format!(
        "credential-command|{AUTHORIZATION_HEADER_SOURCE}|{CREDENTIAL_OPTION_SOURCE}|{SHELL_CREDENTIAL_POLICY_VERSION}"
    )
}

#[cfg(test)]
#[path = "secret_detection_shell_tests.rs"]
mod tests;
