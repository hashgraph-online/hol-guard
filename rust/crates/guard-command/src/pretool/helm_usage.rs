//! Helm's own usage pages.
//!
//! `helm <command> --help` and `helm help <command>` print the usage text the
//! binary carries for that command and exit. Cobra renders it before the
//! command runs, so no chart is fetched, no repository index is read, no
//! release is touched and the cluster is never contacted: the text is the
//! same with no kubeconfig at all.
//!
//! The command has to be one Helm itself carries. An unknown first word is a
//! plugin Helm resolves out of its own plugin directory and runs, and the
//! plugin decides for itself what a help flag means, so `helm diff --help`
//! stays out of this reading and keeps whatever route an unmodelled command
//! takes: the workspace sandbox where the host offers one, review where it
//! does not. That is why the gate carries no negative case for a plugin
//! page; the unit test below is what pins the exclusion, because a contained
//! run is not a review and the gate cannot tell the two apart.
//! Only plain words may stand in front of the flag, which
//! leaves every option that selects a cluster, a namespace or a values file
//! reviewed: `helm install --kubeconfig /tmp/agent.yaml --help` is a
//! kubeconfig the command named, and the usage text is no reason to read it.
//!
//! Still reviewed: every command that does work, `install`, `upgrade`,
//! `uninstall`, `rollback`, `repo add` and `plugin install` among them, with
//! or without a cluster to reach.

/// The commands the Helm binary carries itself.
const BUILTIN_COMMANDS: [&str; 25] = [
    "completion",
    "create",
    "dependency",
    "env",
    "get",
    "history",
    "install",
    "lint",
    "list",
    "package",
    "plugin",
    "pull",
    "push",
    "registry",
    "repo",
    "rollback",
    "search",
    "show",
    "status",
    "template",
    "test",
    "uninstall",
    "upgrade",
    "verify",
    "version",
];

pub(super) fn safe_helm_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && !segment
            .arguments
            .iter()
            .any(|argument| argument.contains(['$', '`', '\n', '\r']))
        && usage_only(
            &segment
                .arguments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
}

/// `helm --help`, `helm help [command...]`, or a command path ending in a
/// help flag with nothing but plain words in front of it.
fn usage_only(words: &[&str]) -> bool {
    let Some((first, rest)) = words.split_first() else {
        return false;
    };
    if matches!(*first, "--help" | "-h") {
        return rest.is_empty();
    }
    if *first == "help" {
        return rest.len() <= 2 && rest.iter().all(|word| plain_command(word));
    }
    if !BUILTIN_COMMANDS.contains(first) {
        return false;
    }
    let Some((flag, named)) = rest.split_last() else {
        return false;
    };
    matches!(*flag, "--help" | "-h")
        && named.len() <= 2
        && named.iter().all(|word| plain_command(word))
}

/// A word that can only name a command: no option, no path, no chart
/// reference and no character a template would carry.
fn plain_command(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
#[path = "helm_usage_tests.rs"]
mod tests;
