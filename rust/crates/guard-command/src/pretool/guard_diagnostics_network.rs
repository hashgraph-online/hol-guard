//! `hol-guard network` reads that stay on this computer, split out of
//! [`super`] so each file keeps one job.

/// The two network protection reads.
///
/// `network` and `network status` print which network mediation backends the
/// running daemon reports, or a fallback that claims nothing when the daemon
/// does not answer. `network check <url>` normalises one URL and reports what
/// the network rules and known-bad URL indicators already saved under the
/// Guard home decide for it. Neither opens a connection to the URL, contacts
/// Guard Cloud or writes anything.
///
/// `network sync` fetches the workspace's signed rules from Guard Cloud and
/// saves them, so it stays under review. Every root override (`--home`,
/// `--guard-home`, `--workspace`) is refused by the exact shapes below: a
/// check against another home's saved rules is not this install's answer.
pub(super) fn network_inspection(words: &[&str]) -> bool {
    let json_flags = words.iter().filter(|word| **word == "--json").count();
    let rest: Vec<&str> = words
        .iter()
        .copied()
        .filter(|word| *word != "--json")
        .collect();
    json_flags <= 1
        && match rest.as_slice() {
            ["network"] | ["network", "status"] => true,
            ["network", "check", url] => checked_url(url),
            _ => false,
        }
}

/// The URL `network check` takes as its one positional argument. A leading
/// dash is refused so the value can never be read as an option the shapes
/// above did not admit.
fn checked_url(url: &str) -> bool {
    !url.starts_with('-') && !url.trim().is_empty() && !url.contains('\0') && url.len() <= 4_096
}
