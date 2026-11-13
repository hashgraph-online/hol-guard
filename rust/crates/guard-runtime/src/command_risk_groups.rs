//! The risk groups a shell command falls in, for Cloud Review.
//!
//! A command ask carries the groups so a workspace can route it to the people
//! who answer that kind of action (deletes, deploys, packages, ...), the same
//! way a held cloud action is routed by the rules that held it. The names are
//! the ones Cloud uses for cloud actions.
//!
//! The groups are a routing hint, not an enforcement decision: nothing here
//! allows or blocks anything. A command Guard cannot place gets no group, and
//! Cloud shows it as "other". Recognition never narrows a group to a safer one.

use super::mcp_proxy_shlex::split;

/// Cloud's group names, in Cloud's display order.
const GROUPS: [&str; 6] = [
    "deletes",
    "bulk_changes",
    "sending_and_sharing",
    "secrets",
    "code_and_deploys",
    "packages_and_scripts",
];

/// Commands that run before another command without changing what it does.
const WRAPPERS: [&str; 9] = [
    "sudo", "doas", "env", "nohup", "time", "nice", "command", "exec", "xargs",
];

const SECRET_PATH_MARKERS: [&str; 14] = [
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".pem",
    ".p12",
    ".key",
    ".aws/credentials",
    ".netrc",
    ".npmrc",
    ".pgpass",
    "credentials.json",
    ".kube/config",
    ".docker/config.json",
];

const PACKAGE_MANAGERS: [&str; 10] = [
    "npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "gem",
];
const PACKAGE_VERBS: [&str; 10] = [
    "install", "i", "add", "ci", "update", "upgrade", "run", "exec", "dlx", "x",
];
const PACKAGE_RUNNERS: [&str; 5] = ["npx", "bunx", "pnpx", "pipx", "uvx"];
const SYSTEM_PACKAGE_MANAGERS: [&str; 6] = ["brew", "apt", "apt-get", "yum", "dnf", "apk"];

const DEPLOY_TOOLS: [(&str, &[&str]); 12] = [
    (
        "kubectl",
        &[
            "apply", "create", "replace", "rollout", "scale", "set", "patch",
        ],
    ),
    ("helm", &["install", "upgrade", "rollback"]),
    ("terraform", &["apply", "import"]),
    ("tofu", &["apply", "import"]),
    ("pulumi", &["up", "deploy"]),
    ("vercel", &["deploy", "--prod", "promote"]),
    ("netlify", &["deploy"]),
    ("fly", &["deploy"]),
    ("flyctl", &["deploy"]),
    ("firebase", &["deploy"]),
    ("wrangler", &["deploy", "publish"]),
    ("serverless", &["deploy"]),
];

/// The groups of `command`, in Cloud's order, or none when nothing is known.
pub(crate) fn command_risk_groups(command: &str) -> Vec<&'static str> {
    let tokens =
        split(command).unwrap_or_else(|| command.split_whitespace().map(str::to_owned).collect());
    let mut found = [false; GROUPS.len()];
    for segment in segments(&tokens) {
        for group in segment_groups(&segment) {
            if let Some(index) = GROUPS.iter().position(|name| *name == group) {
                found[index] = true;
            }
        }
    }
    GROUPS
        .iter()
        .zip(found)
        .filter_map(|(name, hit)| hit.then_some(*name))
        .collect()
}

/// One simple command per segment, split at `;`, `&&`, `||`, `|` and
/// parentheses, with redirections and their targets kept apart.
fn segments(tokens: &[String]) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut current = Segment::default();
    let mut redirect_next = false;
    for token in tokens {
        let is_operator = !token.is_empty() && token.chars().all(|c| ";&|()".contains(c));
        if is_operator {
            out.push(std::mem::take(&mut current));
            continue;
        }
        if !token.is_empty() && token.chars().all(|c| "<>".contains(c)) {
            redirect_next = true;
            continue;
        }
        if redirect_next {
            current.redirects.push(token.clone());
            redirect_next = false;
        } else {
            current.words.push(token.clone());
        }
    }
    out.push(current);
    out.into_iter()
        .filter(|segment| !segment.words.is_empty())
        .collect()
}

#[derive(Default)]
struct Segment {
    words: Vec<String>,
    redirects: Vec<String>,
}

fn program_name(word: &str) -> String {
    word.rsplit('/').next().unwrap_or(word).to_ascii_lowercase()
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The index of the program word, past wrappers, their flags and `NAME=value`.
fn program_index(words: &[String]) -> Option<usize> {
    let mut index = 0;
    loop {
        let word = words.get(index)?;
        if is_assignment(word) {
            index += 1;
            continue;
        }
        if WRAPPERS.contains(&program_name(word).as_str()) {
            index += 1;
            while words
                .get(index)
                .is_some_and(|next| next.starts_with('-') || is_assignment(next))
            {
                index += 1;
            }
            continue;
        }
        return Some(index);
    }
}

fn has(args: &[String], wanted: &str) -> bool {
    args.iter().any(|arg| arg == wanted)
}

/// The first argument that is not a flag.
fn verb(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str)
}

fn names_secret(word: &str) -> bool {
    let lowered = word.to_ascii_lowercase();
    let file = lowered.rsplit('/').next().unwrap_or(&lowered);
    (file == ".env" || file.starts_with(".env."))
        || SECRET_PATH_MARKERS[1..]
            .iter()
            .any(|marker| lowered.contains(marker))
}

fn is_remote_target(word: &str) -> bool {
    let lowered = word.to_ascii_lowercase();
    [
        "s3://", "gs://", "az://", "https://", "http://", "ftp://", "sftp://",
    ]
    .iter()
    .any(|scheme| lowered.starts_with(scheme))
        || (!lowered.starts_with('/')
            && !lowered.starts_with('.')
            && lowered
                .split_once(':')
                .is_some_and(|(host, _)| !host.is_empty() && !host.contains('/')))
}

fn sql_groups(args: &[String]) -> Vec<&'static str> {
    let text = args.join(" ");
    let mut groups = Vec::new();
    if [
        "drop table",
        "drop database",
        "drop schema",
        "truncate",
        "delete from",
    ]
    .iter()
    .any(|statement| text.contains(statement))
    {
        groups.push("deletes");
    }
    if text.contains("update ") && text.contains(" set ") && !text.contains(" where ") {
        groups.push("bulk_changes");
    }
    groups
}

fn segment_groups(segment: &Segment) -> Vec<&'static str> {
    let Some(index) = program_index(&segment.words) else {
        return Vec::new();
    };
    let name = program_name(&segment.words[index]);
    let raw_args = &segment.words[index + 1..];
    let args: Vec<String> = raw_args
        .iter()
        .map(|arg| arg.to_ascii_lowercase())
        .collect();
    let mut groups = Vec::new();
    let sub = verb(&args);
    match name.as_str() {
        "rm" | "rmdir" | "unlink" | "shred" | "trash" | "srm" => groups.push("deletes"),
        "find"
            if has(&args, "-delete")
                || args
                    .windows(2)
                    .any(|pair| pair[0] == "-exec" && pair[1] == "rm") =>
        {
            groups.push("deletes");
        }
        "git" => groups.extend(git_groups(&args)),
        "gh" => groups.extend(gh_groups(&args)),
        "aws" => groups.extend(cloud_storage_groups(
            &args,
            &["rm", "rb", "delete-object", "delete-bucket"],
        )),
        "gsutil" | "gcloud" | "az" => groups.extend(cloud_storage_groups(&args, &["rm", "delete"])),
        "docker" | "podman" => {
            if matches!(sub, Some("rm" | "rmi" | "prune")) || has(&args, "prune") {
                groups.push("deletes");
            }
            if sub == Some("push") {
                groups.push("sending_and_sharing");
            }
        }
        "dropdb" | "dropuser" => groups.push("deletes"),
        "redis-cli"
            if args
                .iter()
                .any(|arg| arg == "flushall" || arg == "flushdb" || arg == "del") =>
        {
            groups.push("deletes")
        }
        "psql" | "mysql" | "sqlite3" | "mongosh" | "clickhouse-client" => {
            groups.extend(sql_groups(&args))
        }
        "curl" | "wget" | "http" | "https" | "xh" => {
            // Case matters here: curl's -F uploads a form, -f only fails quietly.
            let sends = raw_args.iter().any(|arg| {
                matches!(
                    arg.as_str(),
                    "-d" | "-F"
                        | "-T"
                        | "--upload-file"
                        | "--form"
                        | "--post-data"
                        | "--post-file"
                        | "--json"
                ) || arg.starts_with("--data")
                    || arg.starts_with("--form")
                    || (arg.starts_with("-d") && !arg.starts_with("--"))
            }) || raw_args.windows(2).any(|pair| {
                matches!(pair[0].as_str(), "-X" | "--request")
                    && matches!(
                        pair[1].to_ascii_uppercase().as_str(),
                        "POST" | "PUT" | "PATCH" | "DELETE"
                    )
            });
            if sends {
                groups.push("sending_and_sharing");
            }
        }
        "scp" | "rsync" | "sftp" | "ftp" if args.iter().any(|arg| is_remote_target(arg)) => {
            groups.push("sending_and_sharing")
        }
        "mail" | "mailx" | "sendmail" | "mutt" => groups.push("sending_and_sharing"),
        "printenv" => groups.push("secrets"),
        "security"
            if sub.is_some_and(|verb| verb.starts_with("find-") && verb.ends_with("-password")) =>
        {
            groups.push("secrets")
        }
        "op" | "vault" if matches!(sub, Some("read" | "get" | "kv")) => groups.push("secrets"),
        "make" | "just"
            if args
                .iter()
                .any(|arg| arg.contains("deploy") || arg.contains("release")) =>
        {
            groups.push("code_and_deploys")
        }
        _ => {}
    }
    if PACKAGE_MANAGERS.contains(&name.as_str()) {
        if sub.is_some_and(|verb| PACKAGE_VERBS.contains(&verb))
            || (name == "yarn" && sub.is_none())
        {
            groups.push("packages_and_scripts");
        }
        if sub == Some("publish") {
            groups.push("packages_and_scripts");
            groups.push("sending_and_sharing");
        }
        if name == "uv" && args.iter().take(2).any(|arg| arg == "pip") && has(&args, "install") {
            groups.push("packages_and_scripts");
        }
    }
    if PACKAGE_RUNNERS.contains(&name.as_str())
        || (SYSTEM_PACKAGE_MANAGERS.contains(&name.as_str())
            && matches!(sub, Some("install" | "upgrade" | "reinstall" | "add")))
        || (matches!(name.as_str(), "go") && matches!(sub, Some("install" | "get")))
        || (name == "composer" && matches!(sub, Some("install" | "require" | "update")))
    {
        groups.push("packages_and_scripts");
    }
    if let Some((_, verbs)) = DEPLOY_TOOLS.iter().find(|(tool, _)| *tool == name) {
        if args.iter().any(|arg| verbs.contains(&arg.as_str())) {
            groups.push("code_and_deploys");
        }
        if name == "kubectl" && has(&args, "delete") {
            groups.push("deletes");
        }
        if matches!(name.as_str(), "terraform" | "tofu" | "pulumi")
            && matches!(sub, Some("destroy"))
        {
            groups.push("deletes");
        }
        if name == "helm" && matches!(sub, Some("uninstall" | "delete")) {
            groups.push("deletes");
        }
    }
    if name == "kubectl"
        && has(&args, "get")
        && args.iter().any(|arg| arg == "secret" || arg == "secrets")
    {
        groups.push("secrets");
    }
    if name.starts_with("deploy") {
        groups.push("code_and_deploys");
    }
    let reads_secret = matches!(
        name.as_str(),
        "cat"
            | "less"
            | "more"
            | "head"
            | "tail"
            | "bat"
            | "grep"
            | "rg"
            | "cp"
            | "base64"
            | "xxd"
            | "strings"
            | "source"
            | "."
    ) && args.iter().any(|arg| names_secret(arg));
    if reads_secret
        || (matches!(name.as_str(), "scp" | "rsync" | "curl")
            && args
                .iter()
                .any(|arg| names_secret(arg.trim_start_matches('@'))))
    {
        groups.push("secrets");
    }
    if segment.redirects.iter().any(|target| names_secret(target)) {
        groups.push("secrets");
    }
    groups
}

fn git_groups(args: &[String]) -> Vec<&'static str> {
    let mut groups = Vec::new();
    // `git -C dir push`: skip global options and their values.
    let mut rest = args;
    while let Some(first) = rest.first() {
        if matches!(first.as_str(), "-c" | "-C" | "--git-dir" | "--work-tree") {
            rest = rest.get(2..).unwrap_or(&[]);
        } else if first.starts_with('-') {
            rest = &rest[1..];
        } else {
            break;
        }
    }
    let Some((sub, tail)) = rest.split_first() else {
        return groups;
    };
    match sub.as_str() {
        "push" => {
            groups.push("code_and_deploys");
            if tail.iter().any(|arg| {
                arg == "--delete" || arg == "-d" || (arg.starts_with(':') && arg.len() > 1)
            }) {
                groups.push("deletes");
            }
        }
        "branch"
            if tail
                .iter()
                .any(|arg| matches!(arg.as_str(), "-d" | "-D" | "--delete")) =>
        {
            groups.push("deletes")
        }
        "tag"
            if tail
                .iter()
                .any(|arg| matches!(arg.as_str(), "-d" | "--delete")) =>
        {
            groups.push("deletes")
        }
        "clean"
            if tail.iter().any(|arg| {
                (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('f'))
                    || arg == "--force"
            }) =>
        {
            groups.push("deletes")
        }
        "reset" if has(tail, "--hard") => groups.push("code_and_deploys"),
        "rebase" | "filter-branch" | "filter-repo" | "merge" | "cherry-pick" | "revert" => {
            groups.push("code_and_deploys")
        }
        "rm" => groups.push("deletes"),
        "stash"
            if tail
                .first()
                .is_some_and(|arg| arg == "drop" || arg == "clear") =>
        {
            groups.push("deletes")
        }
        _ => {}
    }
    groups
}

fn gh_groups(args: &[String]) -> Vec<&'static str> {
    let mut groups = Vec::new();
    let words: Vec<&str> = args
        .iter()
        .filter(|arg| !arg.starts_with('-'))
        .map(String::as_str)
        .collect();
    match words.as_slice() {
        [_, "delete", ..] | [_, _, "delete", ..] => groups.push("deletes"),
        ["pr", "merge", ..] | ["release", "create", ..] | ["workflow", "run", ..] => {
            groups.push("code_and_deploys")
        }
        ["gist", "create", ..] | ["release", "upload", ..] => groups.push("sending_and_sharing"),
        ["auth", "token", ..] | ["secret", "list" | "set", ..] => groups.push("secrets"),
        _ => {}
    }
    if words.first() == Some(&"repo")
        && args
            .iter()
            .any(|arg| arg == "--visibility=public" || arg == "public")
    {
        groups.push("sending_and_sharing");
    }
    groups
}

fn cloud_storage_groups(args: &[String], delete_verbs: &[&str]) -> Vec<&'static str> {
    let mut groups = Vec::new();
    if args.iter().any(|arg| delete_verbs.contains(&arg.as_str())) {
        groups.push("deletes");
    }
    let copies = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "cp" | "sync" | "mv" | "upload" | "put-object"));
    if copies && args.last().is_some_and(|last| is_remote_target(last)) {
        groups.push("sending_and_sharing");
    }
    if args.iter().any(|arg| arg == "--acl") && args.iter().any(|arg| arg.contains("public")) {
        groups.push("sending_and_sharing");
    }
    if args
        .windows(2)
        .any(|pair| pair[0] == "secretsmanager" && pair[1] == "get-secret-value")
        || args
            .windows(2)
            .any(|pair| pair[0] == "configure" && pair[1] == "get")
    {
        groups.push("secrets");
    }
    if args
        .iter()
        .any(|arg| arg == "deploy" || arg == "update-function-code" || arg == "update-service")
    {
        groups.push("code_and_deploys");
    }
    groups
}

#[cfg(test)]
#[path = "command_risk_groups_tests.rs"]
mod tests;
