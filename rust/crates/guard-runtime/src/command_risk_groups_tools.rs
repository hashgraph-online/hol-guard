//! Groups for specific tools: package managers, deploy tools, SQL clients,
//! `git` and `gh`. HTTP clients and cloud CLIs have their own files.

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

/// Package-manager options before the subcommand that take a value. npm's
/// `-w` takes a workspace name; pnpm's `-w` and yarn's `-W` take none.
const PACKAGE_VALUE_FLAGS: [&str; 15] = [
    "--prefix",
    "-C",
    "--dir",
    "--cwd",
    "--filter",
    "--workspace",
    "--registry",
    "--cache",
    "--userconfig",
    "--directory",
    "--project",
    "--config",
    "-Z",
    "--proxy",
    "--cache-dir",
];

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
    let npm_flags: Vec<&str> = PACKAGE_VALUE_FLAGS.iter().copied().chain(["-w"]).collect();
    let value_flags: &[&str] = if name == "npm" {
        &npm_flags
    } else {
        &PACKAGE_VALUE_FLAGS
    };
    let sub = subcommand(args, value_flags).map(|(_, verb)| verb);
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

/// SQL statements, read as words outside string literals and comments.
pub(super) fn sql_groups(args: &[String]) -> Vec<&'static str> {
    let mut text = String::new();
    let mut in_string = false;
    // Client options are not SQL: `--command` would read as a comment. An
    // attached value (`--command=DROP TABLE x`) is kept. A word with a space
    // before any `=` is SQL even when it starts with `--`. Each argument is
    // its own statement, so a `WHERE` in one never limits another.
    let joined = args
        .iter()
        .filter_map(|arg| {
            let name = arg.split('=').next().unwrap_or(arg);
            if !arg.starts_with('-') || name.contains(char::is_whitespace) {
                Some(arg.as_str())
            } else {
                arg.split_once('=').map(|(_, value)| value)
            }
        })
        .collect::<Vec<_>>()
        .join(";\n");
    let mut chars = joined.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            in_string = !in_string;
            text.push(' ');
        } else if in_string {
            continue;
        } else if c == '-' && chars.next_if_eq(&'-').is_some() {
            while chars.next_if(|next| *next != '\n').is_some() {}
            text.push(' ');
        } else if c == '/' && chars.next_if_eq(&'*').is_some() {
            let mut last = ' ';
            for inner in chars.by_ref() {
                if last == '*' && inner == '/' {
                    break;
                }
                last = inner;
            }
            text.push(' ');
        } else {
            text.push(c);
        }
    }
    let words_of = |statement: &'_ str| -> Vec<String> {
        statement
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|word| !word.is_empty())
            .map(str::to_string)
            .collect()
    };
    let words = words_of(&text);
    let mut groups = Vec::new();
    let deletes = words.windows(2).any(|pair| {
        (pair[0] == "drop" && matches!(pair[1].as_str(), "table" | "database" | "schema"))
            || (pair[0] == "delete" && pair[1] == "from")
    }) || words
        .iter()
        .any(|word| matches!(word.as_str(), "truncate" | "dropdatabase" | "deletemany"));
    if deletes {
        groups.push("deletes");
    }
    // Each statement on its own: `UPDATE a SET x WHERE y; UPDATE a SET x`
    // updates every row in its second statement.
    // A `WHERE` inside a subquery (`SET x = (SELECT ... WHERE ...)`) does not
    // limit the outer update, so only the statement's top level is read.
    let bulk_update = text.split(';').any(|statement| {
        let mut depth = 0usize;
        let top: String = statement
            .chars()
            .map(|c| {
                match c {
                    '(' => depth += 1,
                    ')' => depth = depth.saturating_sub(1),
                    _ if depth == 0 => return c,
                    _ => {}
                }
                ' '
            })
            .collect();
        let words = words_of(&top);
        words
            .iter()
            .position(|word| word == "update")
            .is_some_and(|at| {
                words[at + 1..].iter().any(|word| word == "set")
                    && !words[at + 1..].iter().any(|word| word == "where")
            })
    });
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
