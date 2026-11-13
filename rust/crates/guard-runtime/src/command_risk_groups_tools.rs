//! Groups for specific tools: package managers, deploy tools, HTTP clients,
//! cloud storage, SQL clients, `git` and `gh`.

const PACKAGE_MANAGERS: [&str; 10] = [
    "npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "poetry", "cargo", "gem",
];
const PACKAGE_VERBS: [&str; 10] = [
    "install", "i", "add", "ci", "update", "upgrade", "run", "exec", "dlx", "x",
];
const PACKAGE_RUNNERS: [&str; 5] = ["npx", "bunx", "pnpx", "pipx", "uvx"];
const SYSTEM_PACKAGE_MANAGERS: [&str; 6] = ["brew", "apt", "apt-get", "yum", "dnf", "apk"];

struct DeployTool {
    name: &'static str,
    deploys: &'static [&'static str],
    deletes: &'static [&'static str],
    /// Options before the subcommand that take the next word as a value.
    value_flags: &'static [&'static str],
}

const KUBECTL_FLAGS: &[&str] = &[
    "-n",
    "--namespace",
    "--context",
    "--cluster",
    "--kubeconfig",
    "-s",
    "--server",
    "--user",
    "--as",
    "--as-group",
    "--request-timeout",
];

const DEPLOY_TOOLS: [DeployTool; 12] = [
    DeployTool {
        name: "kubectl",
        deploys: &[
            "apply", "create", "replace", "rollout", "scale", "set", "patch", "edit",
        ],
        deletes: &["delete"],
        value_flags: KUBECTL_FLAGS,
    },
    DeployTool {
        name: "helm",
        deploys: &["install", "upgrade", "rollback"],
        deletes: &["uninstall", "delete"],
        value_flags: &["-n", "--namespace", "--kube-context", "--kubeconfig"],
    },
    DeployTool {
        name: "terraform",
        deploys: &["apply", "import"],
        deletes: &["destroy"],
        value_flags: &[],
    },
    DeployTool {
        name: "tofu",
        deploys: &["apply", "import"],
        deletes: &["destroy"],
        value_flags: &[],
    },
    DeployTool {
        name: "pulumi",
        deploys: &["up", "deploy"],
        deletes: &["destroy"],
        value_flags: &["-s", "--stack", "-C", "--cwd"],
    },
    DeployTool {
        name: "vercel",
        deploys: &["deploy", "promote", "redeploy"],
        deletes: &["remove", "rm"],
        value_flags: &["-t", "--token", "-S", "--scope", "--cwd"],
    },
    DeployTool {
        name: "netlify",
        deploys: &["deploy"],
        deletes: &[],
        value_flags: &[],
    },
    DeployTool {
        name: "fly",
        deploys: &["deploy"],
        deletes: &[],
        value_flags: &["-a", "--app", "-c", "--config"],
    },
    DeployTool {
        name: "flyctl",
        deploys: &["deploy"],
        deletes: &[],
        value_flags: &["-a", "--app", "-c", "--config"],
    },
    DeployTool {
        name: "firebase",
        deploys: &["deploy"],
        deletes: &[],
        value_flags: &["-P", "--project"],
    },
    DeployTool {
        name: "wrangler",
        deploys: &["deploy", "publish"],
        deletes: &[],
        value_flags: &[],
    },
    DeployTool {
        name: "serverless",
        deploys: &["deploy"],
        deletes: &["remove"],
        value_flags: &[],
    },
];

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

/// curl short options whose value follows them, attached or in the next word.
const CURL_VALUE_FLAGS: &str = "AbcCDeEHKmoOQrUuwxYyz";

pub(super) fn has(args: &[String], wanted: &str) -> bool {
    args.iter().any(|arg| arg == wanted)
}

/// The first word that is not an option, past the values of `value_flags`
/// (matched without case, since callers pass lowercased words).
pub(super) fn subcommand<'a>(args: &'a [String], value_flags: &[&str]) -> Option<(usize, &'a str)> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if value_flags
            .iter()
            .any(|flag| flag.eq_ignore_ascii_case(arg))
        {
            index += 2;
        } else if arg.starts_with('-') {
            index += 1;
        } else {
            return Some((index, arg.as_str()));
        }
    }
    None
}

pub(super) fn is_remote_target(word: &str) -> bool {
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

pub(super) fn package_groups(name: &str, args: &[String]) -> Vec<&'static str> {
    let sub = subcommand(args, &[]).map(|(_, verb)| verb);
    let mut groups = Vec::new();
    if PACKAGE_MANAGERS.contains(&name) {
        if sub.is_some_and(|verb| PACKAGE_VERBS.contains(&verb))
            || (name == "yarn" && sub.is_none())
        {
            groups.push("packages_and_scripts");
        }
        if sub == Some("publish") {
            groups.push("packages_and_scripts");
            groups.push("sending_and_sharing");
        }
        if name == "uv" && args.iter().take(2).any(|arg| arg == "pip") && has(args, "install") {
            groups.push("packages_and_scripts");
        }
    }
    if PACKAGE_RUNNERS.contains(&name)
        || (SYSTEM_PACKAGE_MANAGERS.contains(&name)
            && matches!(sub, Some("install" | "upgrade" | "reinstall" | "add")))
        || (name == "go" && matches!(sub, Some("install" | "get")))
        || (name == "composer" && matches!(sub, Some("install" | "require" | "update")))
    {
        groups.push("packages_and_scripts");
    }
    groups
}

/// Deploy tools, matched on their subcommand only, so an object named
/// `apply` or `delete` in `kubectl get deployment apply` is not an action.
pub(super) fn deploy_groups(name: &str, args: &[String]) -> Vec<&'static str> {
    let Some(tool) = DEPLOY_TOOLS.iter().find(|tool| tool.name == name) else {
        return Vec::new();
    };
    let mut groups = Vec::new();
    let sub = subcommand(args, tool.value_flags);
    let verb = sub.map(|(_, verb)| verb);
    if verb.is_some_and(|verb| tool.deploys.contains(&verb))
        || (name == "vercel" && has(args, "--prod"))
    {
        groups.push("code_and_deploys");
    }
    if verb.is_some_and(|verb| tool.deletes.contains(&verb))
        || (matches!(name, "terraform" | "tofu") && verb == Some("apply") && has(args, "-destroy"))
    {
        groups.push("deletes");
    }
    if let Some((index, "get")) = sub.filter(|_| name == "kubectl") {
        let reads_secret = args[index + 1..].iter().any(|arg| {
            arg.split(',')
                .any(|kind| matches!(kind.split('/').next(), Some("secret" | "secrets")))
        });
        if reads_secret {
            groups.push("secrets");
        }
    }
    groups
}

fn is_write_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Whether an HTTP client sends a body, a file or a write request.
/// `raw_args` keep their case: curl's `-F` uploads a form, `-f` fails quietly.
pub(super) fn http_sends(name: &str, raw_args: &[String]) -> bool {
    let long_option = raw_args.iter().any(|arg| {
        [
            "--data",
            "--form",
            "--json",
            "--upload-file",
            "--post-data",
            "--post-file",
            "--body-data",
            "--body-file",
        ]
        .iter()
        .any(|prefix| arg.starts_with(prefix))
            || ["--request=", "--method="]
                .iter()
                .any(|prefix| arg.strip_prefix(prefix).is_some_and(is_write_method))
    });
    let method_option = raw_args.windows(2).any(|pair| {
        matches!(pair[0].as_str(), "-X" | "--request" | "--method") && is_write_method(&pair[1])
    });
    let curl_short = name == "curl"
        && raw_args
            .iter()
            .enumerate()
            .any(|(index, arg)| curl_short_sends(arg, raw_args.get(index + 1)));
    let httpie = matches!(name, "http" | "https" | "xh") && httpie_sends(raw_args);
    long_option || method_option || curl_short || httpie
}

/// A curl short-option word such as `-d`, `-Ffile=@x`, `-sT x` or `-XPOST`.
fn curl_short_sends(arg: &str, next: Option<&String>) -> bool {
    let Some(flags) = arg
        .strip_prefix('-')
        .filter(|flags| !flags.starts_with('-'))
    else {
        return false;
    };
    for (at, flag) in flags.char_indices() {
        match flag {
            'd' | 'F' | 'T' => return true,
            'X' => {
                let attached = &flags[at + 1..];
                let method = if attached.is_empty() {
                    next.map_or("", String::as_str)
                } else {
                    attached
                };
                return is_write_method(method);
            }
            _ if CURL_VALUE_FLAGS.contains(flag) => return false,
            _ => {}
        }
    }
    false
}

/// HTTPie: a write method word, or `name=value`, `name:=json` or `name@file`
/// body items after the URL.
fn httpie_sends(args: &[String]) -> bool {
    let words: Vec<&str> = args
        .iter()
        .filter(|arg| !arg.starts_with('-'))
        .map(String::as_str)
        .collect();
    let Some(first) = words.first() else {
        return false;
    };
    if is_write_method(first) {
        return true;
    }
    let names_method = first.chars().all(|c| c.is_ascii_uppercase());
    words
        .iter()
        .skip(if names_method { 2 } else { 1 })
        .any(|item| (item.contains('=') && !item.contains("==")) || item.contains('@'))
}

pub(super) fn cloud_storage_groups(args: &[String], delete_verbs: &[&str]) -> Vec<&'static str> {
    let mut groups = Vec::new();
    if args.iter().any(|arg| delete_verbs.contains(&arg.as_str())) {
        groups.push("deletes");
    }
    let uploads = args
        .iter()
        .any(|arg| matches!(arg.as_str(), "upload" | "upload-batch" | "put-object"));
    let copies_out = args
        .iter()
        .position(|arg| matches!(arg.as_str(), "cp" | "sync" | "mv"))
        .is_some_and(|at| {
            storage_operands(&args[at + 1..])
                .last()
                .is_some_and(|destination| is_remote_target(destination))
        });
    if uploads || copies_out {
        groups.push("sending_and_sharing");
    }
    if has(args, "--acl") && args.iter().any(|arg| arg.contains("public")) {
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

/// SQL statements, read as words outside string literals.
pub(super) fn sql_groups(args: &[String]) -> Vec<&'static str> {
    let mut text = String::new();
    let mut in_string = false;
    for c in args.join(" ").chars() {
        if c == '\'' {
            in_string = !in_string;
            text.push(' ');
        } else if !in_string {
            text.push(c);
        }
    }
    let words: Vec<&str> = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|word| !word.is_empty())
        .collect();
    let mut groups = Vec::new();
    let deletes = words.windows(2).any(|pair| {
        (pair[0] == "drop" && matches!(pair[1], "table" | "database" | "schema"))
            || (pair[0] == "delete" && pair[1] == "from")
    }) || words
        .iter()
        .any(|word| matches!(*word, "truncate" | "dropdatabase" | "deletemany"));
    if deletes {
        groups.push("deletes");
    }
    let bulk_update = words
        .iter()
        .position(|word| *word == "update")
        .is_some_and(|at| words[at + 1..].contains(&"set") && !words[at + 1..].contains(&"where"));
    if bulk_update {
        groups.push("bulk_changes");
    }
    groups
}

pub(super) fn git_groups(args: &[String]) -> Vec<&'static str> {
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
    let any = |wanted: &[&str]| tail.iter().any(|arg| wanted.contains(&arg.as_str()));
    match sub.as_str() {
        "push" => {
            groups.push("code_and_deploys");
            if any(&["--delete", "-d"])
                || tail.iter().any(|arg| arg.starts_with(':') && arg.len() > 1)
            {
                groups.push("deletes");
            }
        }
        "branch" if any(&["-d", "-D", "--delete"]) => groups.push("deletes"),
        "tag" if any(&["-d", "--delete"]) => groups.push("deletes"),
        "clean"
            if tail.iter().any(|arg| {
                (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('f'))
                    || arg == "--force"
            }) =>
        {
            groups.push("deletes")
        }
        "reset" if any(&["--hard"]) => groups.push("code_and_deploys"),
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

pub(super) fn gh_groups(args: &[String]) -> Vec<&'static str> {
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
