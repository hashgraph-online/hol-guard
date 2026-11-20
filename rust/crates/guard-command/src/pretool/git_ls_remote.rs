//! `git ls-remote origin`: printing the refs the `origin` remote advertises.
//! It writes nothing to the repository, checks nothing out and runs no hook,
//! so the shape only has to pin the remote the transport proof reads and
//! refuse the options that would start a program or send words of the
//! caller's choosing over the connection.

/// The most ref patterns a listing may carry. Patterns only narrow what the
/// remote prints, so the bound exists to keep the shape readable rather than
/// to hold anything back.
const PATTERN_LIMIT: usize = 8;

/// Whether the arguments after `ls-remote` name a plain listing of `origin`:
/// printing options, the literal remote `origin`, and at most
/// [`PATTERN_LIMIT`] ref patterns.
///
/// `--upload-pack`/`-u` names the program the remote runs, `-o`/
/// `--server-option` sends free text to it, and a URL or path operand reaches
/// a remote the transport proof never read. None of them are listed below, so
/// each keeps the review, as does any option Git grows later.
pub(super) fn listing(rest: &[String]) -> bool {
    let mut remote = false;
    let mut patterns = 0;
    let mut operands_only = false;
    for argument in rest {
        if !operands_only && argument == "--" {
            operands_only = true;
            continue;
        }
        if !operands_only && argument.starts_with('-') {
            if !printing_option(argument) {
                return false;
            }
            continue;
        }
        if !remote {
            if argument != "origin" {
                return false;
            }
            remote = true;
            continue;
        }
        patterns += 1;
        if patterns > PATTERN_LIMIT || !pattern(argument) {
            return false;
        }
    }
    remote
}

/// The options that only choose what Git prints: which refs it lists, how it
/// orders them, whether it stays quiet and what it exits with.
fn printing_option(argument: &str) -> bool {
    match argument {
        "--heads" | "--tags" | "-t" | "--refs" | "--quiet" | "-q" | "--exit-code" | "--get-url"
        | "--symref" => true,
        // `-h` is `--heads` here rather than Git's usual help, which is too
        // close a call to admit.
        _ => argument.strip_prefix("--sort=").is_some_and(sort_key),
    }
}

/// The sort keys a listing orders by without reading an object. A remote
/// advertises each ref's name and the object id it points at, so ordering on
/// either of those needs nothing the listing does not already have.
///
/// Every other key is an object's own field, and reaching it opens two doors
/// this proof does not hold shut: `signature` runs the configured
/// `gpg.program` over the object, and in a partial clone any object field
/// sends Git to the promisor remote for an object it is missing, which is a
/// transport the origin proof never saw. So the keys are named rather than
/// spelled, and a key this list does not hold keeps its review.
const SORT_KEYS: [&str; 4] = ["refname", "objectname", "version:refname", "v:refname"];

/// A `--sort` key: one field name, optionally reversed with a leading `-`.
fn sort_key(value: &str) -> bool {
    let key = value.strip_prefix('-').unwrap_or(value);
    SORT_KEYS.contains(&key)
}

/// A ref pattern: the characters a ref name and a glob over one are spelled
/// with. `..` would name a range rather than a ref, so it stays out.
fn pattern(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.contains("..")
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(
                    character,
                    '/' | '-' | '_' | '.' | '*' | '?' | '[' | ']' | '+' | '@'
                )
        })
}

#[cfg(test)]
#[path = "git_ls_remote_tests.rs"]
mod tests;
