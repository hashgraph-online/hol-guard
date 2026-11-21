//! `hol-guard cloud-actions` reads that stay on this computer, split out of
//! [`super`] so each file keeps one job.

/// The two Cloud actions reads that stay on this computer.
///
/// `cloud-actions status --offline` prints the Guard Cloud address, workspace
/// and Cloud actions state from this computer's `hol-guard connect` pairing,
/// and skips the service check, so nothing is sent and nothing is written.
/// Without `--offline` the same command asks Guard Cloud whether it offers
/// Cloud actions, which stays under review.
///
/// `cloud-actions ai-tools configure <tool> --cloud-workspace <id> --dry-run`
/// reads the AI tool's settings file and prints the one entry it would add.
/// The handler branches on `--apply` before it writes or backs up anything, and
/// the parser requires exactly one of `--dry-run` and `--apply`, so naming
/// `--dry-run` is what proves the preview. `--home` and `--guard-home` are
/// refused by the exact shapes below: a preview of another home's settings is
/// not the user's own setup.
///
/// `accounts`, `doctor` (which can save a bundle) and `ai-tools restore` all
/// change saved state or talk to Guard Cloud, and are not admitted; nor are the
/// removed `login`, `logout` and `workspace select`.
pub(super) fn cloud_actions_inspection(words: &[&str]) -> bool {
    let json_flags = words.iter().filter(|word| **word == "--json").count();
    let rest: Vec<&str> = words
        .iter()
        .copied()
        .filter(|word| *word != "--json")
        .collect();
    json_flags <= 1
        && match rest.as_slice() {
            ["cloud-actions", "status", "--offline"] => true,
            ["cloud-actions", "ai-tools", "configure", tool, "--cloud-workspace", id, "--dry-run"]
            | ["cloud-actions", "ai-tools", "configure", tool, "--dry-run", "--cloud-workspace", id] => {
                ai_tool_name(tool) && cloud_workspace_id(id)
            }
            _ => false,
        }
}

/// An AI tool name as the launcher's parser accepts it: a lowercase slug. A
/// leading dash is refused so the name can never be read as an option.
fn ai_tool_name(value: &str) -> bool {
    value.len() <= 63
        && value.starts_with(|first: char| first.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// A Guard Cloud workspace ID: a hyphenated UUID, the only form the parser
/// turns into a workspace. Anything else is a usage error the parser reports.
fn cloud_workspace_id(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups.iter().zip([8, 4, 4, 4, 12]).all(|(group, length)| {
            group.len() == length && group.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

#[cfg(test)]
#[path = "guard_diagnostics_cloud_actions_tests.rs"]
mod tests;
