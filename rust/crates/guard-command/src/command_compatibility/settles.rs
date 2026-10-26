//! Whether an explicit extension Allow may settle uncertainty about a segment,
//! for every command extension rather than one owner at a time.
//!
//! Uncertainty means Guard attributed the segment to a rule it could not fully
//! classify. An explicit Allow for that rule's permission is the user's consent
//! to the action class, so it may settle the segment only while the segment's
//! own shape stays inside what the text proves: no steering environment, no
//! interpreter or nested executor that runs text the attribution only sampled,
//! and no option that changes which authority answers (a remote Docker daemon,
//! another cluster, a proxy program) or runs a program Guard never read. Any
//! shape outside that proof keeps its review, whatever permission is enabled.

use super::{basename, environment, CommandSegmentV1};

/// Programs that run text they receive, or launch a program named by a
/// later argument, so they can assemble any command. An uncertain
/// attribution of their segment only sampled that text, so it never settles.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "ash",
    "pwsh",
    "powershell",
    "cmd",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "osascript",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "env",
    "xargs",
    "eval",
    // Launchers: the segment names another program to run (a busybox
    // applet, a watched/retried/niced command, a Makefile's recipes, a
    // package runner's binary), so the attribution only sampled its text.
    "busybox",
    "watch",
    "timeout",
    "nohup",
    "stdbuf",
    "setsid",
    "nice",
    "chroot",
    "flock",
    "expect",
    "tclsh",
    "make",
    "npx",
    "parallel",
    "sudo",
    "doas",
    "su",
    "runuser",
    "pkexec",
    "ionice",
    "taskset",
    "chrt",
    "unshare",
    "nsenter",
    "firejail",
    "systemd-run",
    "xvfb-run",
    "script",
    "strace",
    "ltrace",
    "uvx",
    "pipx",
    "bunx",
    "pnpx",
];

fn inert_environment(segment: &CommandSegmentV1) -> bool {
    segment
        .environment_names
        .iter()
        .all(|name| environment::inert_environment_name(name))
}

/// kubectl/oc global flags that take a value and may precede the subcommand.
const KUBECTL_GLOBAL_VALUE_FLAGS: &[&str] = &[
    "--as",
    "--as-group",
    "--as-uid",
    "--cache-dir",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--cluster",
    "--context",
    "--kubeconfig",
    "--namespace",
    "--password",
    "--profile",
    "--proxy-url",
    "--request-timeout",
    "--server",
    "--tls-server-name",
    "--token",
    "--user",
    "--username",
    "-n",
];

/// kubectl/oc flags that change which authority answers, or whose credentials
/// it answers with. Like a non-default Docker context, they name a different
/// authority than the one the user reviewed, so they keep their review.
const KUBECTL_AUTHORITY_FLAGS: &[&str] = &[
    "--as",
    "--as-group",
    "--as-uid",
    "--certificate-authority",
    "--client-certificate",
    "--client-key",
    "--cluster",
    "--context",
    "--kubeconfig",
    "--password",
    "--proxy-url",
    "--server",
    "--token",
    "--user",
    "--username",
];

fn flag_name(argument: &str) -> &str {
    argument.split('=').next().unwrap_or(argument)
}

/// Value of an option spelled `--name=value`, `--name value`, `-fvalue`,
/// `-f value`, or `-f=value` for the flag `flag`.
fn option_value<'a>(
    arguments: &'a [String],
    index: usize,
    argument: &'a str,
    flag: &str,
) -> Option<&'a str> {
    if flag.starts_with("--") {
        if let Some((_, value)) = argument.split_once('=') {
            return Some(value);
        }
    }
    if let Some(rest) = argument.strip_prefix(flag) {
        if !rest.is_empty() {
            return Some(rest.strip_prefix('=').unwrap_or(rest));
        }
    }
    if argument == flag {
        return arguments.get(index + 1).map(String::as_str);
    }
    None
}

/// Letters of a bundled short-option argument (`-avz` → `avz`); empty for
/// long options and positionals. Attached values ride along in the letters,
/// which only ever makes the deny checks below fail closed.
fn bundle_letters(argument: &str) -> &str {
    if argument.starts_with('-') && !argument.starts_with("--") && argument.len() > 1 {
        &argument[1..]
    } else {
        ""
    }
}

/// Whether a `gh` segment stays inside what its text proves. Field values
/// loaded from files (`-F`/`--field name=@path`), bodies loaded with
/// `--input`, a `-F` body file outside `api`, or any `--*-file` option, jq
/// programs that reach the environment or load a module, an alternate
/// `--hostname`, and shell expansion inside a value all put content or an
/// authority Guard never read into the request, so they never settle.
/// Literal `--raw-field` values (an `@mention` is text, not a file) and
/// GraphQL variables declared in the document stay settleable.
///
/// An unmodeled subcommand is the one deliberate exception to "a program
/// Guard never read": the unknown GitHub permission's own catalog example
/// is `gh extension run custom-tool`, so enabling it *is* the user's
/// consent to the unverified class. The bounds above still apply to it.
fn github_segment_settles_uncertainty(segment: &CommandSegmentV1) -> bool {
    if !inert_environment(segment) {
        return false;
    }
    let arguments = &segment.arguments;
    // The first word that is not an option (or an option's value) names the
    // subcommand; `-F` is a typed field only under `api`.
    let subcommand = {
        let mut candidate: Option<&str> = None;
        let mut index = 0;
        while let Some(argument) = arguments.get(index) {
            index += 1;
            if matches!(argument.as_str(), "-R" | "--repo" | "--hostname") {
                index += 1;
                continue;
            }
            if !argument.starts_with('-') {
                candidate = Some(argument);
                break;
            }
        }
        candidate
    };
    // A `$name` settles only as a GraphQL variable the same text declares
    // (`mutation($id:ID!)`); any other `$` — `$HOME`, `${...}`, `$(...)` —
    // is a value the shell or the server resolves, not the text Guard read.
    let full_text = arguments.join(" ");
    let declares_variable = |name: &str| full_text.contains(&format!("${name}:"));
    for (index, argument) in arguments.iter().enumerate() {
        if argument.contains("$(")
            || argument.contains('`')
            || argument.contains("${")
            || argument.contains("$'")
            || argument.contains("$\"")
        {
            return false;
        }
        for (position, _) in argument.match_indices('$') {
            let rest = &argument[position + 1..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty()
                && (name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_'))
                && !declares_variable(&name)
            {
                return false;
            }
        }
        let name = flag_name(argument);
        if name == "--input" || name == "--hostname" || name.ends_with("-file") {
            return false;
        }
        let field_flag = if argument.starts_with("-F") && !argument.starts_with("--") {
            Some("-F")
        } else if name == "--field" {
            Some("--field")
        } else {
            None
        };
        if let Some(flag) = field_flag {
            // Outside `api`, `-F` is `--body-file`: its value is a path to a
            // file whose contents Guard never read.
            if flag == "-F" && subcommand != Some("api") {
                return false;
            }
            let Some(value) = option_value(arguments, index, argument, flag) else {
                return false;
            };
            let field_value = value.split_once('=').map_or(value, |(_, rest)| rest);
            if field_value.starts_with('@') {
                return false;
            }
        }
        let jq_flag = if name == "--jq" {
            Some("--jq")
        } else if argument.starts_with("-q") && !argument.starts_with("--") {
            Some("-q")
        } else {
            None
        };
        if let Some(flag) = jq_flag {
            let Some(value) = option_value(arguments, index, argument, flag) else {
                return false;
            };
            let lowered = value.to_ascii_lowercase();
            if lowered.contains("env")
                || lowered.contains("getenv")
                || lowered.contains("import")
                || lowered.contains("include")
            {
                return false;
            }
        }
    }
    true
}

fn kubernetes_segment_settles_uncertainty(segment: &CommandSegmentV1) -> bool {
    if !inert_environment(segment) {
        return false;
    }
    let arguments = &segment.arguments;
    let mut index = 0;
    let mut subcommand: Option<&str> = None;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        let name = flag_name(argument);
        // Cobra takes global flags anywhere on the line, so an authority
        // flag after the verb changes who answers exactly as one before it
        // does. `-s` is the short `--server`.
        if KUBECTL_AUTHORITY_FLAGS.contains(&name)
            || (argument.starts_with("-s") && !argument.starts_with("--"))
        {
            return false;
        }
        if subcommand.is_some() {
            // Only read shapes settle, and only with output the command
            // renders itself: no raw API path, no file of resources to act
            // on, and no output format that reads a template file. The
            // `-f`/`-k` letters deny in any spelling — separate, attached
            // (`-f./x.yaml`), or bundled — not just the exact token.
            if matches!(name, "--raw" | "-f" | "--filename" | "-k" | "--kustomize")
                || bundle_letters(argument).contains('f')
                || bundle_letters(argument).contains('k')
            {
                return false;
            }
            let is_output = name == "-o"
                || name == "--output"
                || (argument.starts_with("-o") && !argument.starts_with("--"));
            if is_output {
                let flag = if name == "--output" { "--output" } else { "-o" };
                let value = option_value(arguments, index - 1, argument, flag);
                if !value.is_some_and(super::domains::output_format_reads_no_file) {
                    return false;
                }
            }
            continue;
        }
        if argument == "--" {
            return false;
        }
        if argument.starts_with("--") {
            if KUBECTL_GLOBAL_VALUE_FLAGS.contains(&name) && !argument.contains('=') {
                index += 1;
            }
            continue;
        }
        if argument.starts_with('-') && argument.len() > 1 {
            // Only `-n` may stand before the verb; any other short flag may
            // carry a value this proof does not model, so it fails closed.
            if argument == "-n" {
                index += 1;
                continue;
            }
            return false;
        }
        subcommand = Some(argument);
    }
    matches!(subcommand, Some("get" | "describe"))
}

/// `-o` keywords whose value names a program to run or a library to load
/// locally, reroutes the connection through one, or hands the connection
/// to state outside the text (an existing control socket).
const SSH_PROGRAM_KEYWORDS: &[&str] = &[
    "proxycommand",
    "proxyjump",
    "proxyusefdpass",
    "localcommand",
    "permitlocalcommand",
    "knownhostscommand",
    "pkcs11provider",
    "securitykeyprovider",
    "remotecommand",
    "xauthlocation",
    "controlpath",
];

/// Whether an ssh-family segment (ssh, scp, sftp) stays inside what its
/// text proves. A config file (`-F`), a control or jump program (`-S`,
/// `-J`), an sftp batch file (`-b`), and `-o` values that name a proxy, a
/// local command, or a provider library all hand execution to something
/// Guard never read, in any spelling: separate, attached, or bundled
/// (`-o` may sit at the end of a bundle, as in `-vo`).
fn ssh_family_segment_settles_uncertainty(segment: &CommandSegmentV1, sftp: bool) -> bool {
    if !inert_environment(segment) {
        return false;
    }
    let arguments = &segment.arguments;
    for (index, argument) in arguments.iter().enumerate() {
        if argument == "--" {
            break;
        }
        let letters = bundle_letters(argument);
        if let Some(position) = letters.find('o') {
            // Flags bundled before the `o` are still options of this
            // command; a program-naming one among them fails as before.
            if letters[..position]
                .chars()
                .any(|letter| matches!(letter, 'S' | 'F' | 'J') || (sftp && letter == 'b'))
            {
                return false;
            }
            let attached = &letters[position + 1..];
            let value = if attached.is_empty() {
                arguments.get(index + 1).map(String::as_str)
            } else {
                Some(attached.strip_prefix('=').unwrap_or(attached))
            };
            let Some(value) = value else {
                return false;
            };
            let lowered = value.trim().to_ascii_lowercase();
            // ssh_config separates a keyword from its value with `=` or
            // whitespace (`-o "LocalCommand touch x"`), so split on both.
            let keyword = lowered
                .split(|c: char| c == '=' || c.is_whitespace())
                .next()
                .unwrap_or("");
            if SSH_PROGRAM_KEYWORDS.contains(&keyword)
                || keyword.starts_with("match")
                || lowered.contains("proxy")
            {
                return false;
            }
            continue;
        }
        if matches!(flag_name(argument), "-S" | "-F" | "-J") {
            return false;
        }
        if letters
            .chars()
            .any(|letter| matches!(letter, 'S' | 'F' | 'J') || (sftp && letter == 'b'))
        {
            return false;
        }
    }
    true
}

fn network_segment_settles_uncertainty(segment: &CommandSegmentV1) -> bool {
    if !inert_environment(segment) {
        return false;
    }
    let arguments: Vec<&str> = segment.arguments.iter().map(String::as_str).collect();
    let any = |names: &[&str]| {
        arguments
            .iter()
            .any(|argument| names.iter().any(|name| flag_name(argument) == *name))
    };
    // A forbidden letter anywhere in a short-option bundle (`-sK`, `-avze`)
    // reaches the same option as its separate spelling.
    let bundled = |letter: char| {
        arguments
            .iter()
            .any(|argument| bundle_letters(argument).contains(letter))
    };
    match basename(segment).as_str() {
        // A config file carries instructions this text never showed.
        "curl" => !any(&["-K", "--config"]) && !bundled('K'),
        // An input file lists more URLs to fetch; `--execute` runs wgetrc
        // commands this text never showed.
        "wget" => {
            !any(&["-i", "--input-file", "--config", "--execute"]) && !bundled('i') && !bundled('e')
        }
        // `-e`/`-c` run a program; a script file runs commands from disk.
        "nc" | "netcat" => {
            !any(&["--exec", "--sh-exec"])
                && !arguments.iter().any(|argument| {
                    argument.starts_with('-')
                        && !argument.starts_with("--")
                        && argument[1..].chars().any(|flag| matches!(flag, 'e' | 'c'))
                })
        }
        "rsync" => !any(&["-e", "--rsh", "--rsync-path", "--daemon", "--config"]) && !bundled('e'),
        "ftp" => !any(&["-s"]) && !bundled('s'),
        _ => true,
    }
}

/// Whether a `sed` segment's scripts are fully visible in its text. A
/// script file (`-f`) is text Guard never read; an `e` command or the
/// `e`/`w` substitution flags run a program or write a file the script
/// names. One substitution or transliteration, with an optional address,
/// is all that settles — the same bound the in-place-edit proof uses.
fn sed_segment_settles_uncertainty(segment: &CommandSegmentV1) -> bool {
    if !inert_environment(segment) {
        return false;
    }
    let arguments = &segment.arguments;
    let mut scripts: Vec<&str> = Vec::new();
    let mut positional: Vec<&str> = Vec::new();
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if argument.starts_with("--") {
            // GNU getopt_long also accepts unambiguous abbreviations of
            // long options (`--fil=script.sed`), which name the same
            // unread file or script as the full spelling.
            let name = flag_name(argument);
            if "--file".starts_with(name) {
                return false;
            }
            if name != "--expression" && "--expression".starts_with(name) {
                return false;
            }
        }
        // An `f` anywhere in a short bundle (`-nf script.sed`) names the
        // same unread script file as `-f`, attached or separate.
        if bundle_letters(argument).contains('f') {
            return false;
        }
        if matches!(argument.as_str(), "-e" | "--expression") {
            match arguments.get(index) {
                Some(script) => {
                    scripts.push(script);
                    index += 1;
                }
                None => return false,
            }
            continue;
        }
        if let Some(script) = argument.strip_prefix("--expression=") {
            scripts.push(script);
            continue;
        }
        let letters = bundle_letters(argument);
        if !letters.is_empty() {
            // Walk a short bundle the way getopt does: `-ne SCRIPT` and
            // `-nes|a|b|e` carry a script after the no-value letters, and
            // that script has to prove itself like any other. A letter
            // this walk does not know may take a value, so it fails closed.
            for (offset, letter) in letters.char_indices() {
                match letter {
                    'n' | 'E' | 'r' | 's' | 'u' | 'z' | 'a' => continue,
                    'e' => {
                        let rest = &letters[offset + 1..];
                        if !rest.is_empty() {
                            scripts.push(rest);
                        } else if let Some(script) = arguments.get(index) {
                            scripts.push(script);
                            index += 1;
                        } else {
                            return false;
                        }
                        break;
                    }
                    // The rest of the bundle is the in-place backup suffix.
                    'i' | 'I' => break,
                    _ => return false,
                }
            }
            continue;
        }
        if argument.starts_with('-') && argument.len() > 1 {
            // `-i` (either dialect's spelling), `-E`, `-n` and friends: the
            // script still has to prove itself below. The BSD `-i ''`
            // spelling leaves an empty first positional, which the script
            // check rejects — fail closed rather than guess.
            continue;
        }
        positional.push(argument);
    }
    if scripts.is_empty() {
        match positional.first() {
            Some(script) => scripts.push(script),
            None => return false,
        }
    }
    scripts.iter().all(|script| sed_script_settles(script))
}

/// Scan one sed address (`12`, `$`, `/regex/`, with an optional `,second`)
/// starting at `index`; returns the index just past it.
fn scan_sed_address(bytes: &[u8], mut index: usize) -> Option<usize> {
    let first = *bytes.get(index)?;
    if first == b'$' {
        index += 1;
    } else if first.is_ascii_digit() {
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
    } else if first == b'/' {
        index = scan_sed_delimited(bytes, index + 1, b'/')?;
    } else {
        return Some(index);
    }
    if bytes.get(index) == Some(&b',') {
        let second = *bytes.get(index + 1)?;
        if second == b'$' {
            index += 2;
        } else if second.is_ascii_digit() {
            index += 1;
            while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
        } else if second == b'/' {
            index = scan_sed_delimited(bytes, index + 2, b'/')?;
        } else {
            return None;
        }
    }
    Some(index)
}

/// Scan to the next unescaped `delimiter`; returns the index just past it.
fn scan_sed_delimited(bytes: &[u8], mut index: usize, delimiter: u8) -> Option<usize> {
    while let Some(byte) = bytes.get(index) {
        index += 1;
        match byte {
            b'\\' => index += 1,
            byte if *byte == delimiter => return Some(index),
            _ => {}
        }
    }
    None
}

fn sed_script_settles(script: &str) -> bool {
    let bytes = script.as_bytes();
    if script.is_empty() || script.len() > 1024 || script.contains('\n') {
        return false;
    }
    let Some(mut index) = scan_sed_address(bytes, 0) else {
        return false;
    };
    let command = bytes.get(index).copied();
    index += 1;
    let delimiter = bytes.get(index).copied().unwrap_or(0);
    if !matches!(
        delimiter,
        b'/' | b'|' | b'#' | b',' | b':' | b'@' | b'!' | b'%' | b'+' | b'~' | b'_' | b'='
    ) {
        return false;
    }
    index += 1;
    let Some(next) = scan_sed_delimited(bytes, index, delimiter) else {
        return false;
    };
    index = next;
    match command {
        Some(b's') => {
            let Some(next) = scan_sed_delimited(bytes, index, delimiter) else {
                return false;
            };
            // Substitution flags only: `e` executes the result as a command
            // and `w` writes it to a file, so both stay reviewed.
            bytes[next..]
                .iter()
                .all(|flag| matches!(flag, b'g' | b'p' | b'i' | b'm' | b'0'..=b'9'))
        }
        Some(b'y') => scan_sed_delimited(bytes, index, delimiter) == Some(bytes.len()),
        _ => false,
    }
}

/// Whether an explicit extension Allow may settle uncertainty about this
/// segment, whichever extension owns the uncertain rule. Owners with their
/// own authority or program-running shapes (Git, Docker, kubectl, the
/// network tools) keep their narrower proofs; every other program settles
/// only with an inert environment and no interpreter in the segment.
pub(crate) fn segment_settles_uncertainty(
    segment: &CommandSegmentV1,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    // A wrapper between the shell and the executable (sudo, env, a shell
    // launcher) runs the segment under authority or text the segment's own
    // shape does not prove, whichever owner the segment belongs to.
    if !segment.wrapper_chain.is_empty() {
        return false;
    }
    match basename(segment).as_str() {
        "git" => {
            super::git::subcommand_settles_uncertainty(segment)
                && !super::git::runs_configured_program(segment)
                && super::git_repository_routes_verified(segment, context)
        }
        "docker" => super::domains::docker_segment_settles_uncertainty(segment),
        "gh" => github_segment_settles_uncertainty(segment),
        "kubectl" | "oc" => kubernetes_segment_settles_uncertainty(segment),
        "ssh" => ssh_family_segment_settles_uncertainty(segment, false),
        "scp" => ssh_family_segment_settles_uncertainty(segment, false),
        "sftp" => ssh_family_segment_settles_uncertainty(segment, true),
        "curl" | "wget" | "nc" | "netcat" | "rsync" | "ftp" => {
            network_segment_settles_uncertainty(segment)
        }
        "sed" | "gsed" => sed_segment_settles_uncertainty(segment),
        name if INTERPRETERS.contains(&name) || name.starts_with("python") => false,
        "find" => {
            inert_environment(segment)
                && !segment.arguments.iter().any(|argument| {
                    matches!(flag_name(argument), "-exec" | "-execdir" | "-ok" | "-okdir")
                })
        }
        _ => inert_environment(segment),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CommandSpanV1;

    fn segment(executable: &str, arguments: &[&str]) -> CommandSegmentV1 {
        CommandSegmentV1 {
            text: String::new(),
            tokens: Vec::new(),
            executable: Some(executable.to_owned()),
            arguments: arguments.iter().map(ToString::to_string).collect(),
            environment_names: Vec::new(),
            wrapper_chain: Vec::new(),
            path_overridden: false,
            execution_context: "root".to_owned(),
            pipeline_index: 0,
            span: CommandSpanV1 {
                source: "normalized".to_owned(),
                start: 0,
                end: 0,
            },
        }
    }

    fn settles(executable: &str, arguments: &[&str]) -> bool {
        segment_settles_uncertainty(
            &segment(executable, arguments),
            crate::pretool::PathContext::default(),
        )
    }

    #[test]
    fn every_owner_family_has_a_settleable_shape() {
        assert!(settles(
            "kubectl",
            &["-n", "prod", "describe", "secret", "db"]
        ));
        assert!(settles(
            "curl",
            &["-T", "report.txt", "https://example.invalid/up"]
        ));
        assert!(settles("rm", &["-rf", "build"]));
        assert!(settles("gh", &["some-unmodeled-command"]));
        assert!(settles("docker", &["ps"]));
        assert!(settles(
            "kubectl",
            &["get", "pods", "-n", "prod", "-o", "yaml"]
        ));
        assert!(settles("ssh", &["host", "ls", "-la"]));
        assert!(settles("scp", &["report.txt", "host:/tmp/"]));
        assert!(settles("sed", &["-i", "s|old|new|", "src/app.ts"]));
        assert!(settles("sed", &["-i", "1,3s|a|b|g", "src/app.ts"]));
        assert!(settles("sed", &["-ne", "s|a|b|", "src/app.ts"]));
        assert!(settles("sed", &["-i.bak", "-E", "s|a|b|", "src/app.ts"]));
    }

    #[test]
    fn unbounded_shapes_never_settle() {
        // A different authority answers.
        assert!(!settles(
            "kubectl",
            &["--context", "prod", "get", "secret", "db"]
        ));
        // Not a read shape.
        assert!(!settles("kubectl", &["exec", "web-0", "--", "cat", "x"]));
        // A template file the command would read.
        assert!(!settles(
            "kubectl",
            &["get", "secret", "db", "-o", "go-template-file=./tmpl"]
        ));
        // Instructions or programs from files Guard never read.
        assert!(!settles("curl", &["-K", "curlrc", "-T", "f", "https://h"]));
        assert!(!settles(
            "gh",
            &["api", "x/y/git/blobs", "-F", "content=@file.txt"]
        ));
        assert!(!settles("gh", &["api", "graphql", "--input", "-"]));
        assert!(!settles("gh", &["api", "user", "--jq", "env.GH_TOKEN"]));
        assert!(!settles("rsync", &["-e", "sh", "f", "host:/tmp/"]));
        assert!(!settles("nc", &["-e", "/bin/sh", "host", "4444"]));
        assert!(!settles("find", &[".", "-exec", "rm", "{}", ";"]));
        // Bundled and attached spellings reach the same options.
        assert!(!settles("curl", &["-sK", "curlrc", "https://h"]));
        assert!(!settles("curl", &["-Kcurlrc", "https://h"]));
        assert!(!settles("rsync", &["-avze", "ssh", "f", "host:/tmp/"]));
        assert!(!settles("wget", &["--execute=robots=off", "https://h"]));
        assert!(!settles("wget", &["-i", "urls.txt"]));
        // kubectl authority flags bind after the verb too (cobra takes
        // global flags anywhere), and `-s` is the short `--server`.
        assert!(!settles(
            "kubectl",
            &["get", "secret", "db", "--context", "prod", "-o", "yaml"]
        ));
        assert!(!settles(
            "kubectl",
            &["get", "secret", "db", "--kubeconfig=prod.yaml"]
        ));
        assert!(!settles(
            "kubectl",
            &["-s", "https://other.invalid:8443", "get", "pods"]
        ));
        assert!(!settles(
            "kubectl",
            &["get", "pods", "-ogo-template-file=./tmpl"]
        ));
        // ssh-family programs and keyword options.
        assert!(!settles("ssh", &["-o", "ProxyCommand=sh -c x", "host"]));
        assert!(!settles("ssh", &["-oProxyJump=bastion", "host"]));
        assert!(!settles("ssh", &["-vo", "ProxyCommand=sh -c x", "host"]));
        assert!(!settles("ssh", &["-voKnownHostsCommand=cat %f", "host"]));
        assert!(!settles(
            "ssh",
            &["-o", "PKCS11Provider=/tmp/lib.so", "host"]
        ));
        assert!(!settles("scp", &["-Sprog", "f", "host:/tmp/"]));
        assert!(!settles(
            "scp",
            &["-o", "LocalCommand=touch x", "f", "host:/tmp/"]
        ));
        assert!(!settles("sftp", &["-b", "batch.txt", "host"]));
        // Outside `gh api`, `-F` is a body file; an alternate host is a
        // different authority.
        assert!(!settles(
            "gh",
            &["issue", "create", "--title", "Bug", "-F", "notes.md"]
        ));
        assert!(!settles(
            "gh",
            &["api", "--hostname", "ghe.invalid", "user"]
        ));
        assert!(!settles("gh", &["api", "x/y", "-Fcontent=@file.txt"]));
        // A sed script from a file, or one that executes or writes, is text
        // Guard never bounded.
        assert!(!settles("sed", &["-i", "-f", "script.sed", "f.txt"]));
        assert!(!settles("sed", &["-i", "s|a|b|e", "f.txt"]));
        assert!(!settles("sed", &["-i", "s|a|b|w out.txt", "f.txt"]));
        // Interpreters run text the attribution only sampled.
        assert!(!settles("python3", &["-c", "import os"]));
        assert!(!settles("sh", &["-c", "rm -rf build"]));
        // Attached and bundled kubectl file flags reach the same options
        // as the separate spelling.
        assert!(!settles("kubectl", &["get", "pods", "-f./x.yaml"]));
        assert!(!settles("kubectl", &["get", "pods", "-k./kust"]));
        // Bundled and abbreviated sed script-file spellings.
        assert!(!settles("sed", &["-nf", "script.sed", "f.txt"]));
        assert!(!settles("sed", &["--fil=script.sed", "f.txt"]));
        assert!(!settles("sed", &["--exp=s|a|b|e", "f.txt"]));
        // A script carried by `e` inside a short bundle is checked too.
        assert!(!settles(
            "sed",
            &["-ne", "1e touch x", "-e", "s|a|b|", "f.txt"]
        ));
        assert!(!settles("sed", &["-nes|a|b|e", "s|x|y|", "target"]));
        assert!(!settles("sed", &["-l", "5", "s|a|b|", "f.txt"]));
        // ssh keywords separate from their value with whitespace too, and
        // an xauth program or an existing control socket is state outside
        // the text.
        assert!(!settles("ssh", &["-o", "LocalCommand touch x", "host"]));
        assert!(!settles(
            "ssh",
            &["-o", "XAuthLocation=/tmp/evil-xauth", "host"]
        ));
        assert!(!settles("ssh", &["-o", "ControlPath=/tmp/sock", "host"]));
        // Launchers run a program named by a later argument.
        assert!(!settles("watch", &["docker", "ps"]));
        assert!(!settles("busybox", &["ls", "-la"]));
        assert!(!settles("timeout", &["5", "curl", "https://h"]));
    }

    #[test]
    fn a_wrapped_segment_never_settles() {
        let mut wrapped = segment("rm", &["-rf", "build"]);
        wrapped.wrapper_chain = vec!["sudo".to_owned()];
        assert!(!segment_settles_uncertainty(
            &wrapped,
            crate::pretool::PathContext::default()
        ));
    }

    #[test]
    fn a_steering_environment_prefix_never_settles() {
        let mut steered = segment("rm", &["-rf", "build"]);
        steered.environment_names = vec!["SOME_STEER".to_owned()];
        assert!(!segment_settles_uncertainty(
            &steered,
            crate::pretool::PathContext::default()
        ));
        let mut steered_docker = segment("docker", &["ps"]);
        steered_docker.environment_names = vec!["DOCKER_HOST".to_owned()];
        assert!(!segment_settles_uncertainty(
            &steered_docker,
            crate::pretool::PathContext::default()
        ));
    }
}
