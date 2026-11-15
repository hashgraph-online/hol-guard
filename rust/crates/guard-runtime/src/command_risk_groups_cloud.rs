//! Cloud CLIs: storage deletes and uploads, secret reads and deploys.

use super::tools::{has, is_remote_target};

/// Storage options that take no value; any other `--option` takes one.
const STORAGE_BOOLEAN_FLAGS: [&str; 18] = [
    "--recursive",
    "--dryrun",
    "--dry-run",
    "--quiet",
    "--no-progress",
    "--only-show-errors",
    "--follow-symlinks",
    "--no-follow-symlinks",
    "--delete",
    "--exact-timestamps",
    "--size-only",
    "--no-sign-request",
    "--force",
    "--no-guess-mime-type",
    "--no-verify-ssl",
    "--debug",
    "--no-paginate",
    "--no-clobber",
];

struct CloudCli {
    name: &'static str,
    deletes: &'static [&'static str],
    /// Options that take the next word as a value.
    value_flags: &'static [&'static str],
    /// How many leading words name the service and action.
    action_words: usize,
    /// Leading release-track words that come before the service.
    tracks: &'static [&'static str],
}

const CLOUD_CLIS: [CloudCli; 4] = [
    CloudCli {
        name: "aws",
        deletes: &["rm", "rb", "delete-object", "delete-bucket"],
        value_flags: &[
            "--profile",
            "--region",
            "--output",
            "--endpoint-url",
            "--query",
            "--ca-bundle",
            "--color",
            "--cli-read-timeout",
            "--cli-connect-timeout",
        ],
        action_words: 2,
        tracks: &[],
    },
    CloudCli {
        name: "gcloud",
        deletes: &["rm", "delete"],
        value_flags: &[
            "--project",
            "--account",
            "--configuration",
            "--format",
            "--verbosity",
            "--region",
            "--zone",
            "--impersonate-service-account",
        ],
        action_words: 4,
        tracks: &["alpha", "beta", "preview"],
    },
    CloudCli {
        name: "az",
        deletes: &["delete"],
        value_flags: &[
            "--subscription",
            "--resource-group",
            "-g",
            "--output",
            "-o",
            "--query",
        ],
        action_words: 4,
        tracks: &[],
    },
    CloudCli {
        name: "gsutil",
        deletes: &["rm", "rb"],
        value_flags: &["-o", "-h", "-u"],
        action_words: 1,
        tracks: &[],
    },
];

/// Cloud CLIs, matched on the words that name the service and action, past
/// global options and their values, so `aws s3 ls --profile deploy` lists.
pub(super) fn cloud_storage_groups(name: &str, args: &[String]) -> Vec<&'static str> {
    let Some(cli) = CLOUD_CLIS.iter().find(|cli| cli.name == name) else {
        return Vec::new();
    };
    let mut words = command_words(args, cli.value_flags).into_iter().peekable();
    words.next_if(|(_, word)| cli.tracks.contains(word));
    let actions: Vec<(usize, &str)> = words.take(cli.action_words).collect();
    let is = |wanted: &[&str]| actions.iter().any(|(_, word)| wanted.contains(word));
    let pair = |first: &str, second: &str| {
        actions
            .windows(2)
            .any(|words| words[0].1 == first && words[1].1 == second)
    };
    let mut groups = Vec::new();
    let mirror_delete =
        (is(&["sync"]) && has(args, "--delete")) || (is(&["rsync"]) && has(args, "-d"));
    if is(cli.deletes) || mirror_delete {
        groups.push("deletes");
    }
    let uploads = is(&["upload", "upload-batch", "put-object"]);
    let copies_out = actions
        .iter()
        .find(|(_, word)| matches!(*word, "cp" | "sync" | "mv" | "rsync"))
        .is_some_and(|(at, _)| {
            storage_operands(&args[at + 1..])
                .last()
                .is_some_and(|destination| is_remote_target(destination))
        });
    if uploads || copies_out {
        groups.push("sending_and_sharing");
    }
    let public_acl = args.iter().enumerate().any(|(at, arg)| {
        let value = match arg.strip_prefix("--acl") {
            Some("") => args.get(at + 1).map(String::as_str),
            Some(attached) => attached.strip_prefix('='),
            None => None,
        };
        value.is_some_and(|value| value.contains("public"))
    });
    if public_acl {
        groups.push("sending_and_sharing");
    }
    if pair("secretsmanager", "get-secret-value") || pair("configure", "get") {
        groups.push("secrets");
    }
    if is(&["deploy", "update-function-code", "update-service"]) {
        groups.push("code_and_deploys");
    }
    groups
}

/// The words that are not options or option values, with their positions.
fn command_words<'a>(args: &'a [String], value_flags: &[&str]) -> Vec<(usize, &'a str)> {
    let mut words = Vec::new();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if value_flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case(arg))
        {
            index += 2;
            continue;
        }
        if !arg.starts_with('-') {
            words.push((index, arg.as_str()));
        }
        index += 1;
    }
    words
}

/// The source and destination words of a copy, past options and their values.
fn storage_operands(args: &[String]) -> Vec<&str> {
    let mut operands = Vec::new();
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if !arg.starts_with('-') {
            operands.push(arg.as_str());
            index += 1;
            continue;
        }
        let takes_value = (arg.starts_with("--")
            && !arg.contains('=')
            && !STORAGE_BOOLEAN_FLAGS.contains(&arg.as_str()))
            || matches!(arg.as_str(), "-h" | "-a" | "-z" | "-p" | "-o");
        index += if takes_value { 2 } else { 1 };
    }
    operands
}
