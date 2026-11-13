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
            // The one URL is held to the same rule as `explain`'s target: a
            // leading dash is refused so it can never be read as an option.
            ["network", "check", url] => super::explained_target(url),
            _ => false,
        }
}

#[cfg(test)]
#[path = "guard_diagnostics_network_tests.rs"]
mod tests;
