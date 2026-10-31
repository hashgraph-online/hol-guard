//! The verbs that name a group of a package manager's subcommands.
//!
//! `bun pm`, `pnpm store` and `yarn cache` are not effects. Each one names a
//! family, and the subcommand after it is what decides whether the command
//! reaches a registry: `bun pm ls` prints the dependency tree already on
//! disk, `bun pm trust <name>` runs a package's install scripts. The registry
//! scan in [`super`] reads one word at a time, so it refused the group word
//! itself and kept every local read spelled with one out of the sandbox,
//! where each reported a review the user then had to answer by hand.

/// Whether `behind` is a group word followed by a subcommand that only
/// reports what is already on disk.
///
/// `pm`, `store` and `cache` are the words [`super::REGISTRY_VERBS`] holds
/// for the effects their families also carry — `bun pm cache rm`, `pnpm
/// store add`, `yarn cache clean` — so a group word on its own says nothing
/// yet and the subcommand after it decides. The subcommands are an
/// allowlist and nothing else passes, so a family's own writing and fetching
/// verbs — `rm`, `add`, `prune`, `clean`, `trust`, `pack`, `migrate` — keep
/// the review they have today, and so does a group word carrying no
/// subcommand at all. `bun pm whoami` is absent with them: it sends the
/// stored registry credential to ask whose it is, which is the one thing in
/// the family that reaches the network.
pub(super) fn reads(behind: &[&str]) -> bool {
    let Some((verb, rest)) = behind.split_first() else {
        return false;
    };
    let Some((subcommand, options)) = rest.split_first() else {
        return false;
    };
    let reporting = match *verb {
        // `bun pm cache` prints the cache directory; `bun pm cache rm`
        // empties it, and is refused by the operand check below.
        "pm" => matches!(
            *subcommand,
            "ls" | "bin"
                | "cache"
                | "hash"
                | "hash-string"
                | "hash-print"
                | "trusted"
                | "untrusted"
                | "default-trusted"
        ),
        "store" => matches!(*subcommand, "path" | "status"),
        "cache" => matches!(*subcommand, "ls" | "list" | "dir"),
        _ => false,
    };
    reporting && options.iter().all(|option| inert(option))
}

/// Whether `option` behind a reporting subcommand only shapes its output.
///
/// Every word here is a flag, so a second positional — the package `bun pm
/// cache rm` empties or `pnpm store add` fetches — is refused by the leading
/// dash alone. An inline value is read the way the options before a verb are
/// read, so one naming a place outside the directory the command runs in
/// keeps the command out rather than moving the report somewhere the sandbox
/// does not bound. A value given as the next word needs no rule of its own:
/// it carries no dash, so it is refused as a positional.
fn inert(option: &str) -> bool {
    option.starts_with('-')
        && match option.split_once('=') {
            Some((_, value)) => super::options::inert_value(value),
            None => true,
        }
}

#[cfg(test)]
#[path = "workspace_contained_package_groups_tests.rs"]
mod tests;
