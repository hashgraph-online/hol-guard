//! Guard's own read-only diagnostics.
//!
//! Agents routinely run these to learn why a command was paused. Only the bare
//! launcher and the exact argument shapes below are admitted, so repair, fix,
//! incident, uninstall, policy and other control subcommands keep the normal
//! review or critical-floor path.
//!
//! The reading verbs are admitted as a group (`record_inspection`): `events`,
//! `exceptions`, `policies`, `receipts`, `history`, `advisories`, `inventory`
//! and `trust`, each printing what the local store already holds. An agent
//! that has to ask for an approval before it can read its own approval
//! history learns nothing from the pause, so these stay silent; the
//! subcommands that write or leave the machine do not.
//!
//! `hol-guard settings` is admitted with its read-only views (`list`, `explain`
//! and `doctor`, each with an optional `--json`). They print the saved
//! configuration and the posture summary. `settings set`, `approval-password`
//! and `approval-totp` change state and keep the normal review path.
//!
//! `hol-guard dashboard` is admitted beside them. It starts Guard's own daemon
//! when it is not running and opens the local approval center in the browser.
//! The session token travels only to the browser; the printed URL is redacted.
//! It changes no policy, approval or harness state, and it takes no root
//! override, so it cannot point Guard at another home.
//!
//! `hol-guard approvals`, `approvals list` and `approvals retry-hint <id>` are
//! admitted too (`approval_inspection`), along with `approvals wait <id>`.
//! They inspect approval state; waiting observes a decision without consuming it.
//! Resolving, resuming, opening, unlocking and
//! clearing approvals are separate subcommands and stay reviewed or blocked. The
//! bare `approvals` form, like `dashboard`, may open the user's own approval
//! center once for the next pending request; it resolves nothing. Building the
//! queue snapshot also applies a due Watch-posture revert, which only moves a
//! posture back to protected and never weakens one.
//!
//! `hol-guard runtime` and `hol-guard runtime posture` print the executables
//! the configured MCP servers would launch and the advisory coverage Guard
//! already holds for them. Nothing is started, no Cloud call is made and no
//! setting, approval or policy changes; the bare form runs the same read.
//! These four shapes are exact: `runtime posture --instances`, which asks
//! which of those runtimes are running here and writes what it saw into the
//! Guard home, matches none of them and is reviewed like any other command
//! that reads other processes.
//!
//! Like every other bare-name proof here, the inherited `PATH` is a host trust
//! input: Rust has no resolved executable identity. A launcher sitting in the
//! working directory is the one shadow this proof can see, so it fails closed
//! when one exists or when the working directory is unknown.

use std::path::Path;

const SHADOW_NAMES: &[&str] = &[
    "hol-guard",
    "hol-guard.exe",
    "hol-guard.cmd",
    "hol-guard.bat",
];

pub(super) fn safe_hol_guard_segment(
    arguments: &[String],
    cwd: Option<&str>,
    pipeline_index: usize,
) -> bool {
    cwd.is_some_and(|cwd| !cwd_shadows_launcher(Path::new(cwd)))
        && (safe_hol_guard_arguments(arguments)
            || (pipeline_index == 0
                && super::pytest_contained::safe_pytest_contained_arguments(arguments, cwd)))
}

/// Whether any word of `text` runs Guard's own launcher.
///
/// Every word is read, not only the first: in `true && hol-guard ...`,
/// `(hol-guard ...)` or `X=1 hol-guard ...` the launcher is a later segment
/// whose own proof would still admit it. Words are split at whitespace and at
/// every shell operator, assignment and substitution character, so a prefix
/// cannot hide one. Quoting is removed first, because the shell removes it
/// before the lookup: `'hol-guard'` and `hol"guard"` both reach the same
/// program. A path-spelled launcher answers yes too, by its last component.
/// Over-reading costs only a review of a wrapped list that mentions the name.
pub(super) fn names_launcher(text: &str) -> bool {
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ';' | '&' | '|' | '(' | ')' | '{' | '}' | '`' | '$' | '<' | '>' | '='
            )
    })
    .any(|word| {
        let dequoted: String = word
            .chars()
            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
            .collect();
        let name = dequoted.rsplit('/').next().unwrap_or_default();
        SHADOW_NAMES
            .iter()
            .any(|shadow| name.eq_ignore_ascii_case(shadow))
    })
}

/// Whether the working directory could supply the program a bare `hol-guard`
/// reaches. A launcher file sitting in it wins the bare-name lookup, and a
/// generated shim directory (`package-shims/bin`) is the one place a frozen
/// launcher runs its first word as a script instead of parsing it, so a run
/// from inside one is refused too.
fn cwd_shadows_launcher(cwd: &Path) -> bool {
    !cwd.is_absolute()
        || (cwd.file_name().is_some_and(|name| name == "bin")
            && cwd
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == "package-shims"))
        || SHADOW_NAMES.iter().any(|name| {
            // A directory cannot be executed through a bare-name lookup;
            // files and symlinks (even to directories) still shadow.
            cwd.join(name)
                .symlink_metadata()
                .is_ok_and(|metadata| !metadata.is_dir())
        })
}

/// A path spelling of the very Guard binary that is running this review.
///
/// An agent waiting on an approval raised by the desktop application spells
/// the launcher inside the installed bundle, and a path spelling drops the
/// read-only admission the bare name gets, so every `approvals wait` on a
/// Desktop install raised a second approval row for the row it was already
/// waiting on.
///
/// The installed location proves nothing on its own: `/Applications` is
/// writable by the account the agent runs as, so a session can create a
/// bundle at any path and fill it with a program of its own. What it cannot
/// do is make this process run from the file it planted, so the running
/// executable is the bound. [`safe_hol_guard_arguments`] still decides which
/// subcommands the admission covers.
pub(super) fn this_runtime_executable(executable: &str) -> bool {
    running_executable(executable, std::env::current_exe().ok().as_deref())
}

fn running_executable(executable: &str, running: Option<&Path>) -> bool {
    let (path, Some(running)) = (Path::new(executable), running) else {
        return false;
    };
    // A relative spelling resolves against this process's working directory,
    // not the one the reviewed command would run in. The name screen is the
    // one the admission arm dispatches on, so a path that could not reach
    // that arm never pays for the two lookups below.
    if !path.is_absolute() || super::executable_basename(executable) != "hol-guard" {
        return false;
    }
    let (Ok(spelled), Ok(running)) = (path.canonicalize(), running.canonicalize()) else {
        return false;
    };
    spelled == running && spelled.is_file()
}

pub(super) fn safe_hol_guard_arguments(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    matches!(
        words.as_slice(),
        ["--version"]
            | ["status" | "doctor" | "settings"]
            | ["daemon", "status"]
            | ["status" | "doctor" | "settings", "--json"]
            | ["settings", "list" | "explain" | "doctor"]
            | ["settings", "list" | "explain" | "doctor", "--json"]
            | ["daemon", "status", "--json"]
            | ["dashboard"]
            | ["dashboard", "--json"]
            | ["runtime"]
            | ["runtime", "--json"]
            | ["runtime", "posture"]
            | ["runtime", "posture", "--json"]
    ) || help_request(&words)
        || command_inspection(&words)
        || approval_inspection(&words)
        || record_inspection(&words)
        || posture_inspection(&words)
}

/// `repair --dry-run`, the recovery path's own preview: every repair step
/// branches on the dry run before it reads any state it would change, and the
/// report names what it would do.
///
/// `package-shims status` reads as a posture check of the same kind and is
/// deliberately absent. Its handler resolves the package-firewall entitlement
/// through a refresh first, and for an install whose cloud proof has gone
/// stale that refresh writes refresh state under the guard home and
/// synchronises with Guard Cloud. A status read that heals is not the
/// effect-free shape this admission proves, so it stays under review until
/// the status path can report without healing.
fn posture_inspection(words: &[&str]) -> bool {
    let json_flags = words.iter().filter(|word| **word == "--json").count();
    let rest: Vec<&str> = words
        .iter()
        .copied()
        .filter(|word| *word != "--json")
        .collect();
    json_flags <= 1 && matches!(rest.as_slice(), ["repair", "--dry-run"])
}

/// The approval queue and the retry hint of one resolved request. The
/// decision subcommands (`approve`, `deny`), `resume`, `open`, `lock`,
/// `unlock` and `clear-history`, and every root override (`--home`,
/// `--guard-home`, `--workspace`), are not admitted. `open` launches the
/// user's own approval center rather than printing anything, so it stays on
/// the review path with the other launches.
fn approval_inspection(words: &[&str]) -> bool {
    match words {
        ["approvals"]
        | ["approvals", "--json"]
        | ["approvals", "list"]
        | ["approvals", "list", "--json"] => true,
        ["approvals", "retry-hint" | "wait", id]
        | ["approvals", "retry-hint" | "wait", id, "--json"] => request_id(id),
        ["approvals", "wait", id, "--timeout", seconds]
        | ["approvals", "wait", id, "--timeout", seconds, "--json"] => {
            request_id(id) && seconds.parse::<u16>().is_ok_and(|seconds| seconds <= 600)
        }
        _ => false,
    }
}

fn request_id(id: &str) -> bool {
    !id.starts_with('-')
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// `hol-guard command test|explain <text>` classifies one command without
/// running it or writing Guard state, and `command extensions [id]` lists the
/// loaded command extensions. Root overrides (`--home`, `--guard-home`,
/// `--workspace`) and the `controls` and `setup` subcommands are not admitted.
fn command_inspection(words: &[&str]) -> bool {
    let ["command", rest @ ..] = words else {
        return false;
    };
    let (head, inspected) = match rest.iter().position(|word| *word == "--") {
        Some(separator) => (&rest[..separator], Some(&rest[separator + 1..])),
        None => (rest, None),
    };
    let json_flags = head.iter().filter(|word| **word == "--json").count();
    let head: Vec<&str> = head
        .iter()
        .copied()
        .filter(|word| *word != "--json")
        .collect();
    json_flags <= 1
        && match (head.as_slice(), inspected) {
            (["test" | "explain", text], None) => !text.starts_with('-') && inspected_text(text),
            (["test" | "explain"], Some([text])) => inspected_text(text),
            (["extensions"], None) => true,
            (["extensions", id], None) => extension_id(id),
            _ => false,
        }
}

fn inspected_text(text: &str) -> bool {
    !text.trim().is_empty() && !text.contains('\0') && text.len() <= 4_096
}

fn extension_id(id: &str) -> bool {
    !id.starts_with(['-', '.'])
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// `--help` for the launcher or a documented subcommand. The parser prints
/// usage and exits before any subcommand runs. The leading word must name a
/// known subcommand: a frozen launcher treats a leading word naming a package
/// manager as a shim script path, which the working directory could supply.
///
/// A leading `guard` is the launcher's no-op prefix (`hol-guard guard --help`
/// runs `hol-guard --help`), so it is dropped before the same check.
fn help_request(words: &[&str]) -> bool {
    let words = match words {
        ["guard", rest @ ..] => rest,
        _ => words,
    };
    match words {
        ["help", rest @ ..] => help_path(rest),
        [rest @ .., "--help" | "-h"] => help_path(rest),
        _ => false,
    }
}

/// The subcommand path a help request names. Only the leading word carries the
/// shim risk the launcher has to rule out, so it is the only one matched
/// against the known names. A subcommand's own verbs are never enumerated here:
/// the list would go stale every time the CLI grows one, and `hol-guard command
/// test --help` would ask for approval while `hol-guard command --help` stays
/// silent. A verb only has to be shaped like one, which keeps out flags, paths
/// and anything a value could carry. Nested verbs are read the same way to the
/// parser's own depth, so `hol-guard command controls patterns --help` prints
/// its usage as quietly as the shallower paths do.
fn help_path(words: &[&str]) -> bool {
    match words {
        [] => true,
        [subcommand, verbs @ ..] => {
            HELP_SUBCOMMANDS.contains(subcommand)
                && verbs.len() <= MAX_HELP_VERBS
                && !verbs
                    .first()
                    .is_some_and(|verb| VERBS_TAKING_A_REMAINDER.contains(&(*subcommand, *verb)))
                && verbs.iter().all(|verb| subcommand_verb(verb))
        }
    }
}

/// Verbs whose parser takes a trailing `argparse.REMAINDER`, named with the
/// subcommand that reaches them. `hol-guard verified-read local cat --help`
/// puts `--help` into that remainder, so the bounded read runs instead of
/// usage printing. The same reason keeps `protect`, `pytest-contained` and
/// `run-shim` out of `HELP_SUBCOMMANDS` one level up; here only the verb is
/// affected, so `verified-read --help` and `verified-read github-pr --help`
/// still print their usage.
const VERBS_TAKING_A_REMAINDER: &[(&str, &str)] = &[("verified-read", "local")];

/// How deep a help path may go below its subcommand. Guard's deepest nest is
/// two verbs below the subcommand (`command controls patterns`), and a path
/// longer than the parser has is a usage error, not a run.
const MAX_HELP_VERBS: usize = 2;

fn subcommand_verb(word: &str) -> bool {
    word.starts_with(|first: char| first.is_ascii_alphabetic())
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Launcher words whose `--help` output is safe to print without a review.
///
/// This tracks the launcher's own parser set so an agent reading the CLI never
/// collects an approval row. Three subcommands are deliberately absent:
/// `protect`, `pytest-contained` and `run-shim` each take a trailing
/// `argparse.REMAINDER`, so `hol-guard protect npm --help` would run `npm
/// --help` rather than print help. A verb one level down can swallow a help
/// flag the same way; [`VERBS_TAKING_A_REMAINDER`] names those.
const HELP_SUBCOMMANDS: &[&str] = &[
    "abom",
    "admin",
    "advisories",
    "aibom",
    "allow",
    "approvals",
    "apps",
    "bootstrap",
    "bridge",
    "cloud",
    "cloud-review",
    "command",
    "commands",
    "connect",
    "contained-write",
    "daemon",
    "dashboard",
    "deny",
    "desktop",
    "detect",
    "device",
    "diff",
    "disconnect",
    "doctor",
    "events",
    "exceptions",
    "explain",
    "export",
    "health-leases",
    "history",
    "hook",
    "hooks",
    "import",
    "init",
    "install",
    "inventory",
    "list",
    "login",
    "mcp",
    "mdm",
    "network",
    "package-shims",
    "policies",
    "policy",
    "preflight",
    "receipts",
    "remote-pair",
    "repair",
    "retry-hint",
    "risk-report",
    "run",
    "runtime",
    "scan",
    "secrets",
    "security-level",
    "service",
    "set",
    "settings",
    "show",
    "skills",
    "start",
    "status",
    "stop",
    "supply-chain",
    "sync",
    "test-eval",
    "trust",
    "uninstall",
    "update",
    "validate",
    "verified-read",
];

/// Guard's own read-only records: the local event log, the active exceptions,
/// the remembered rules, the receipts, the decision history, the cached
/// advisories, the artifact inventory and the local trust posture. Each prints
/// what Guard already holds and writes nothing.
///
/// The subcommands that leave the local store are not admitted: `advisories
/// sync` and `inventory --sync` report to Guard Cloud, and `policies clear`,
/// `repair` and `migrate-local-integrity` rewrite remembered rules, as do
/// `trust setup`, `test` and `reset`. Every root override (`--home`,
/// `--guard-home`, `--workspace`) is refused by the exact shapes below.
fn record_inspection(words: &[&str]) -> bool {
    let json_flags = words.iter().filter(|word| **word == "--json").count();
    let rest: Vec<&str> = words
        .iter()
        .copied()
        .filter(|word| *word != "--json")
        .collect();
    json_flags <= 1
        && match rest.as_slice() {
            ["events" | "exceptions" | "receipts" | "history" | "advisories" | "inventory"
            | "policies" | "trust"]
            | ["advisories", "list"]
            | ["policies", "verify" | "integrity-status"]
            | ["trust", "status"] => true,
            ["events", "--name", value]
            | ["exceptions", "--harness", value]
            | ["policies", "--harness", value]
            | ["advisories", "list", "--severity", value] => plain_value(value),
            ["advisories" | "history", "explain", id] => extension_id(id),
            _ => false,
        }
}

/// A single literal selector: a harness, a dotted event name or a severity.
/// Nothing a path, a flag or a second word could be written with is admitted,
/// and a leading dot or dash is refused so the value can be neither a relative
/// path nor an option.
fn plain_value(value: &str) -> bool {
    value.len() <= 64
        && value.starts_with(|first: char| first.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
#[path = "guard_diagnostics_tests.rs"]
mod tests;
