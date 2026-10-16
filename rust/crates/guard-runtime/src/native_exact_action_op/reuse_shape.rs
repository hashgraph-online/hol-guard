//! Compound commands and argv-bound programs whose approve-once retry stays
//! bound to the reviewed request.
//!
//! A retry may reuse a review only when nothing outside the reviewed text can
//! change what it runs. Each command of a pipeline or list must be bound on its
//! own; redirects may only name plain files. A remote program fed a local file
//! on standard input is bound to that file's content.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::fs_path::sha256_hex;
use super::launcher_sets::{is_code_launcher, is_direct_reusable};

const SEPARATORS: [&str; 4] = ["|", "||", "&&", ";"];
const WRITE_REDIRECTS: [&str; 4] = [">", ">>", ">&", "&>"];
const READ_REDIRECT: &str = "<";
const MAX_STDIN_BYTES: u64 = 4 * 1024 * 1024;
const STDIN_DOMAIN: &[u8] = b"hol-guard.native-review-stdin-binding.v1\0";

/// Programs whose effect their argv determines once their options are checked.
const ARGV_BOUND_COMMANDS: &[&str] = &[
    "basename",
    "cmp",
    "column",
    "comm",
    "cp",
    "cut",
    "date",
    "df",
    "diff",
    "dirname",
    "du",
    "echo",
    "false",
    "file",
    "find",
    "fold",
    "hostname",
    "id",
    "jq",
    "kubectl",
    "ln",
    "ls",
    "md5sum",
    "mkdir",
    "mv",
    "nl",
    "oc",
    "paste",
    "printf",
    "pwd",
    "readlink",
    "realpath",
    "rev",
    "rm",
    "rmdir",
    "seq",
    "sha1sum",
    "sha256sum",
    "shasum",
    "sleep",
    "sort",
    "tac",
    "tee",
    "test",
    "touch",
    "tr",
    "tree",
    "true",
    "uname",
    "uniq",
    "which",
    "whoami",
    "yq",
];
const FIND_RUNS_PROGRAM: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];
/// Built-in verbs; anything else may resolve to a `kubectl-<verb>` plugin.
const KUBECTL_VERBS: &[&str] = &[
    "annotate",
    "api-resources",
    "api-versions",
    "attach",
    "auth",
    "cluster-info",
    "cordon",
    "delete",
    "describe",
    "drain",
    "events",
    "exec",
    "explain",
    "get",
    "label",
    "logs",
    "port-forward",
    "rollout",
    "scale",
    "taint",
    "top",
    "uncordon",
    "version",
    "wait",
];
const KUBECTL_VALUE_OPTIONS: &[&str] = &[
    "-n",
    "--namespace",
    "--context",
    "--cluster",
    "--user",
    "-s",
    "--server",
    "--request-timeout",
    "-v",
];

/// What binds a reusable retry beyond the reviewed request itself.
pub(super) enum Reuse {
    Argv,
    /// The digest of the local files a remote program reads on standard input.
    Stdin(String),
}

impl Reuse {
    /// Domain-separated bytes appended to the binding, or `None` for argv.
    pub(super) fn extra(&self) -> Option<Vec<u8>> {
        match self {
            Self::Argv => None,
            Self::Stdin(digest) => Some([STDIN_DOMAIN, digest.as_bytes()].concat()),
        }
    }
}

/// One command of a list or pipeline.
struct Command<'a> {
    words: Vec<&'a str>,
    reads: Vec<&'a str>,
    piped: bool,
}

/// The reuse binding of `tokens` split as the shell would, or `None`.
pub(super) fn shaped(tokens: &[String], cwd: Option<&Path>) -> Option<Reuse> {
    let commands = commands(tokens)?;
    let mut fed = Vec::new();
    for command in &commands {
        // A variable can name a different file on the retry.
        if command.words.iter().any(|word| word.contains('$')) {
            return None;
        }
        let (executable, arguments) = command.words.split_first()?;
        if executable.contains(['/', '\\', '=', '$']) || executable.starts_with('.') {
            return None;
        }
        let name = executable.to_lowercase();
        if is_code_launcher(&name) {
            return None;
        }
        let remote_stdin = runs_remote_program(&name, arguments);
        if remote_stdin && command.piped {
            // Piped text becomes the remote program's input or source.
            return None;
        }
        if is_direct_reusable(&name) {
            if !super::binding::legacy_arguments_bound(&name, arguments) {
                return None;
            }
        } else if !argv_bound(&name, arguments) {
            return None;
        }
        if !remote_command_bound(&name, arguments, !command.reads.is_empty()) {
            return None;
        }
        if remote_stdin {
            for target in &command.reads {
                fed.push(stdin_digest(target, cwd)?);
            }
        }
    }
    if fed.is_empty() {
        return Some(Reuse::Argv);
    }
    Some(Reuse::Stdin(sha256_hex(fed.join("\n").as_bytes())))
}

fn commands(tokens: &[String]) -> Option<Vec<Command<'_>>> {
    let mut commands = Vec::new();
    let mut current = Command {
        words: Vec::new(),
        reads: Vec::new(),
        piped: false,
    };
    let mut iter = tokens.iter().map(String::as_str);
    while let Some(token) = iter.next() {
        if SEPARATORS.contains(&token) {
            if current.words.is_empty() {
                return None;
            }
            let piped = token == "|";
            commands.push(std::mem::replace(
                &mut current,
                Command {
                    words: Vec::new(),
                    reads: Vec::new(),
                    piped,
                },
            ));
        } else if WRITE_REDIRECTS.contains(&token) || token == READ_REDIRECT {
            let target = iter.next().filter(|target| plain_target(target))?;
            if current.words.is_empty() {
                return None;
            }
            if token == READ_REDIRECT {
                current.reads.push(target);
            }
        } else if is_punctuation(token) || token.contains(['(', ')']) {
            // Parentheses may open a subshell or a process substitution.
            return None;
        } else {
            current.words.push(token);
        }
    }
    if current.words.is_empty() {
        return None;
    }
    commands.push(current);
    Some(commands)
}

fn is_punctuation(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|character| ";&|<>".contains(character))
}

fn plain_target(target: &str) -> bool {
    !target.is_empty()
        && !is_punctuation(target)
        && !target.contains(['$', '~', '*', '?', '[', '{', '(', ')'])
}

/// The argv-bound programs and the options that would load code instead.
fn argv_bound(name: &str, arguments: &[&str]) -> bool {
    if !ARGV_BOUND_COMMANDS.contains(&name) || arguments.iter().any(|word| word.contains('$')) {
        return false;
    }
    match name {
        "find" => !arguments
            .iter()
            .any(|word| FIND_RUNS_PROGRAM.contains(word)),
        // getopt accepts any unambiguous prefix of a long option.
        "sort" => !arguments
            .iter()
            .any(|word| long_option_prefix(word, "compress-program", 3)),
        // Modules load from search paths outside the reviewed text.
        "jq" | "yq" => !arguments.iter().any(|word| {
            long_option_prefix(word, "from-file", 3)
                || long_option_prefix(word, "library-path", 3)
                || word.contains("import")
                || word.contains("include")
                || (word.starts_with('-') && !word.starts_with("--") && word.contains(['f', 'L']))
        }),
        "kubectl" | "oc" => kubectl_bound(arguments),
        _ => true,
    }
}

/// Whether `word` is `--<option>` abbreviated to at least `shortest` letters.
fn long_option_prefix(word: &str, option: &str, shortest: usize) -> bool {
    word.strip_prefix("--")
        .and_then(|rest| rest.split('=').next())
        .is_some_and(|name| name.len() >= shortest.min(option.len()) && option.starts_with(name))
}

/// Short kubectl flags that take no value; `-Rf` bundles `-R` and `-f`.
const KUBECTL_BOOLEAN_SHORT: &[char] = &['A', 'R', 'i', 'q', 't', 'w'];

/// Whether a bundle of short flags names a manifest or kustomization.
fn bundles_manifest(word: &str, verb: &str) -> bool {
    let Some(flags) = word.strip_prefix('-').filter(|rest| !rest.starts_with('-')) else {
        return false;
    };
    for flag in flags.chars() {
        if flag == 'k' || (flag == 'f' && verb != "logs") {
            return true;
        }
        if !KUBECTL_BOOLEAN_SHORT.contains(&flag) && flag != 'f' {
            // The rest of the word is this flag's value.
            return false;
        }
    }
    false
}

fn kubectl_verb<'a>(arguments: &[&'a str]) -> Option<(&'a str, usize)> {
    let mut index = 0;
    while let Some(word) = arguments.get(index) {
        if word.starts_with("--kubeconfig") {
            return None;
        }
        if KUBECTL_VALUE_OPTIONS.contains(word) {
            index += 2;
        } else if word.starts_with('-') {
            index += 1;
        } else {
            return Some((*word, index));
        }
    }
    None
}

fn kubectl_bound(arguments: &[&str]) -> bool {
    let Some((verb, at)) = kubectl_verb(arguments) else {
        return false;
    };
    if !KUBECTL_VERBS.contains(&verb) {
        return false;
    }
    // Manifests and kustomizations are mutable files; `logs -f` follows.
    let end = arguments[at..]
        .iter()
        .position(|word| *word == "--")
        .map_or(arguments.len(), |offset| at + offset);
    !arguments[at..end].iter().any(|word| {
        word.starts_with("--kubeconfig")
            || word.starts_with("--filename")
            || word.starts_with("--kustomize")
            || bundles_manifest(word, verb)
    })
}

/// The program `kubectl exec` runs in the container after `--`: one bound by
/// its argv there, or a launcher whose whole program is the bound standard
/// input. A script or module stored in the container could change unseen.
fn remote_command_bound(name: &str, arguments: &[&str], fed: bool) -> bool {
    if !matches!(name, "kubectl" | "oc")
        || kubectl_verb(arguments).is_none_or(|(verb, _)| verb != "exec")
    {
        return true;
    }
    let Some(at) = arguments.iter().position(|word| *word == "--") else {
        return false;
    };
    let Some((executable, remote)) = arguments[at + 1..].split_first() else {
        return false;
    };
    if executable.contains(['/', '\\', '=', '$']) || executable.starts_with('.') {
        return false;
    }
    let executable = executable.to_lowercase();
    if is_code_launcher(&executable) {
        return fed
            && match remote.iter().position(|word| *word == "-") {
                Some(stdin) => remote[..stdin]
                    .iter()
                    .all(|word| word.starts_with("--input-type=")),
                None => remote.is_empty(),
            };
    }
    if is_direct_reusable(&executable) {
        super::binding::legacy_arguments_bound(&executable, remote)
    } else {
        argv_bound(&executable, remote)
    }
}

/// `kubectl exec` and `kubectl attach` pass standard input to the container.
fn runs_remote_program(name: &str, arguments: &[&str]) -> bool {
    matches!(name, "kubectl" | "oc")
        && kubectl_verb(arguments).is_some_and(|(verb, _)| matches!(verb, "exec" | "attach"))
}

fn stdin_digest(target: &str, cwd: Option<&Path>) -> Option<String> {
    let path = Path::new(target);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.filter(|directory| directory.is_absolute())?.join(path)
    };
    // A FIFO or a device would block the read or never end.
    let metadata = std::fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_STDIN_BYTES {
        return None;
    }
    let mut content = Vec::new();
    File::open(&path)
        .ok()?
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut content)
        .ok()?;
    if content.len() as u64 > MAX_STDIN_BYTES {
        return None;
    }
    Some(format!("{target}\0{}", sha256_hex(&content)))
}

/// Whether `tokens` holds no punctuation, so the legacy single-program check
/// applies unchanged.
pub(super) fn is_simple(tokens: &[String]) -> bool {
    !tokens.iter().any(|token| is_punctuation(token))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::super::binding::payload_reuse;
    use super::Reuse;

    fn bound(command: &str) -> bool {
        matches!(payload_reuse(command, None), Some(Reuse::Argv))
    }

    #[test]
    fn argv_bound_lists_and_pipelines_reuse_their_review() {
        for command in [
            "kubectl get secret app -n prod -o yaml | grep password",
            "kubectl --context staging -n web logs -f deploy/api --tail 50",
            "oc describe pod api-0",
            "kubectl rollout restart deployment/api -n web",
            "rm -rf node_modules",
            "rm -rf /work/app/build && mkdir -p /work/app/build",
            "ls -la > listing.txt 2>&1",
            "find . -name '*.log' -delete",
            "sort a | uniq -c | sort -rn | head -n 5",
            "cat < notes.txt",
            "jq .version package.json",
            "echo done; date",
            "kubectl -nkube-system get pods; true",
            "kubectl exec api-0 -- ls /app",
            "kubectl logs -f api-0 && true",
            "sort --check a",
        ] {
            assert!(bound(command), "{command}");
        }
    }

    #[test]
    fn code_loaded_outside_the_reviewed_text_stays_unbound() {
        for command in [
            "kubectl apply -f deploy.yaml",
            "kubectl delete -f deploy.yaml",
            "kubectl delete -k overlays/prod",
            "kubectl --kubeconfig ./kc get pods",
            "kubectl get pods --kubeconfig=./kc",
            "kubectl neat get pods",
            "kubectl config view --raw",
            "cat run.js | kubectl exec -i api-0 -- node -",
            "kubectl exec -i api-0 -- node - < run.js",
            "ls | sh",
            "ls | xargs rm",
            "ls & ls",
            "ls |& cat",
            "ls <<< x",
            "ls <> f",
            "git status && ls",
            "node build.js | cat",
            "find . -exec rm {} +",
            "jq -f filter.jq data.json",
            "jq --from-file=filter.jq data.json",
            "sort --compress-program=gzip a",
            "rm -rf $TARGET",
            "echo hi > $OUT",
            "echo hi > ~/out",
            "FOO=1 ls && ls",
            "./ls; ls",
            "ls #x; rm -rf build",
            "awk 1 a | cat",
            "ls ;",
            "; ls",
            "kubectl delete -Rf ./manifests",
            "kubectl delete -Rk overlays/prod",
            "kubectl exec api-0 -- node run.mjs",
            "kubectl exec api-0 -- sh /app/job.sh",
            "kubectl exec api-0 -- /app/run",
            "kubectl exec api-0 ls",
            "cat <(sh /tmp/job.sh)",
            "cat < (x)",
            "(rm -rf build); ls",
            "cat $FILE; true",
            "sort --compress-prog=gzip a",
            "sort --com=gzip a",
            "jq --library-path ./lib . data.json",
            "jq --library=./lib . data.json",
            "jq 'import \"m\" as m; m::f' data.json",
            "jq 'include \"m\"; .' data.json",
        ] {
            assert!(payload_reuse(command, None).is_none(), "{command}");
        }
    }

    fn scratch() -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("guard-reuse-shape-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn stdin_digest(command: &str, cwd: &Path) -> String {
        match payload_reuse(command, Some(cwd)) {
            Some(Reuse::Stdin(digest)) => digest,
            _ => panic!("{command} is not bound to its standard input"),
        }
    }

    #[test]
    fn a_remote_program_fed_a_local_file_binds_to_the_file_content() {
        let directory = scratch();
        let script = directory.join("run.mjs");
        std::fs::write(&script, "console.log(1)\n").unwrap();
        let command = "kubectl exec -i api-0 -n web -- node --input-type=module - < run.mjs";
        let first = stdin_digest(command, &directory);
        assert_eq!(first, stdin_digest(command, &directory));
        std::fs::write(&script, "console.log(2)\n").unwrap();
        assert_ne!(first, stdin_digest(command, &directory));
        let absolute = format!(
            "kubectl exec -i api-0 -- node - < {}",
            // The shell reads `\` as an escape; `C:/...` is still absolute.
            script.to_string_lossy().replace('\\', "/")
        );
        assert!(payload_reuse(&absolute, None).is_some());
        assert!(payload_reuse(
            "kubectl exec -i api-0 -- node - < missing.mjs",
            Some(&directory)
        )
        .is_none());
        assert!(payload_reuse(command, Some(Path::new("relative"))).is_none());
        std::fs::write(directory.join("input.txt"), "y\n").unwrap();
        stdin_digest("kubectl attach -i api-0 < input.txt", &directory);
        assert!(payload_reuse(
            "kubectl exec -i api-0 -- node -r ./hook.js - < run.mjs",
            Some(&directory)
        )
        .is_none());
        assert!(payload_reuse(
            "kubectl exec -i api-0 -- node run.mjs < run.mjs",
            Some(&directory)
        )
        .is_none());
        #[cfg(unix)]
        {
            let device = "kubectl exec -i api-0 -- node - < /dev/null";
            assert!(payload_reuse(device, None).is_none());
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
