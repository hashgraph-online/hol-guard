//! Read-only `kubectl` queries and the `export KUBECONFIG=...` that selects
//! their cluster.
//!
//! Only verbs that list, describe or print cluster state are proven, and every
//! option is allowlisted. Secrets stay reviewed under any spelling, and so do
//! options that move the API server, credentials or impersonation, raise log
//! verbosity (which prints bearer tokens), read templates from local files, or
//! hit raw API paths. Unknown verbs stay reviewed because `kubectl` runs a
//! `kubectl-<verb>` plugin from `PATH` for them. ConfigMaps often hold
//! credentials in practice, so `describe` of a ConfigMap and any ConfigMap
//! output beyond names and summary columns keep the review or the read
//! permission. `kubectl logs` of one pod or workload is a read too
//! (`kubectl_logs`): it prints what the workload wrote and moves nothing out
//! of the session, which any later step that sends it elsewhere still has to
//! pass.
//!
//! A kubeconfig can run code (`exec` credential plugins) and read local files
//! (`tokenFile`, client keys), so an explicitly named one must pass
//! [`trust::trusted_kubeconfig`].

#[path = "kubeconfig_trust.rs"]
mod trust;

#[path = "kubectl_logs.rs"]
mod logs;

/// Options that take no value.
const FLAGS: [&str; 10] = [
    "-A",
    "--all-namespaces",
    "--client",
    "--containers",
    "--ignore-not-found",
    "--namespaced",
    "--no-headers",
    "--recursive",
    "--show-kind",
    "--show-labels",
];

/// Options whose value only filters, sorts or bounds the printed state.
const VALUE_OPTIONS: [&str; 16] = [
    "--api-group",
    "--api-version",
    "--chunk-size",
    "--context",
    "--field-selector",
    "--for",
    "-l",
    "-L",
    "--label-columns",
    "-n",
    "--namespace",
    "--request-timeout",
    "--revision",
    "--selector",
    "--sort-by",
    "--timeout",
];

/// Output formats printed to stdout. The `*-file` forms read a local file.
const OUTPUT_FORMATS: [&str; 8] = [
    "custom-columns",
    "go-template",
    "json",
    "jsonpath",
    "jsonpath-as-json",
    "name",
    "wide",
    "yaml",
];

const TOP_RESOURCES: [&str; 6] = ["no", "node", "nodes", "po", "pod", "pods"];

/// Formats that print only names or summary columns, never object data.
const SUMMARY_FORMATS: [&str; 2] = ["name", "wide"];

/// kubectl's own verbs. An unrecognised first word is handed to a
/// `kubectl-<verb>` plugin from `PATH`, which would read the help flag itself
/// instead of printing kubectl's text, so only these names reach
/// [`usage_only`].
const BUILTIN_VERBS: [&str; 44] = [
    "annotate",
    "api-resources",
    "api-versions",
    "apply",
    "attach",
    "auth",
    "autoscale",
    "certificate",
    "cluster-info",
    "completion",
    "config",
    "cordon",
    "cp",
    "create",
    "debug",
    "delete",
    "describe",
    "diff",
    "drain",
    "edit",
    "events",
    "exec",
    "explain",
    "expose",
    "get",
    "kustomize",
    "label",
    "logs",
    "options",
    "patch",
    "plugin",
    "port-forward",
    "proxy",
    "replace",
    "rollout",
    "run",
    "scale",
    "set",
    "taint",
    "top",
    "uncordon",
    "untaint",
    "version",
    "wait",
];

/// `kubectl <verb> --help` and `kubectl options`.
///
/// Cobra answers the help flag with that command's usage text and exits
/// before kubectl builds a client, so the command reads no kubeconfig and
/// contacts no API server whatever verb, resource or namespace stands in
/// front of the flag. `options` prints the same global list with no verb at
/// all. The flag has to be the last word, because anything behind it is an
/// operand kubectl would act on.
fn usage_only(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let [verb, rest @ ..] = words.as_slice() else {
        return false;
    };
    if !BUILTIN_VERBS.contains(verb) {
        return false;
    }
    if rest.is_empty() {
        return *verb == "options";
    }
    let Some((flag, named)) = rest.split_last() else {
        return false;
    };
    matches!(*flag, "--help" | "-h")
        && named.len() <= 2
        && named.iter().all(|word| plain_word(word))
}

/// A verb, resource or name, so it selects a usage page rather than naming a
/// file, a server or a value.
fn plain_word(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && word.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '/')
        })
}

pub(super) fn safe_kubectl_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    if model.dialect != "posix" || segment.pipeline_index != 0 {
        return false;
    }
    let arguments = &segment.arguments;
    if arguments
        .iter()
        .any(|argument| argument.contains(['$', '`', '\n', '\r']))
    {
        return false;
    }
    if usage_only(arguments) {
        return true;
    }
    let mut positionals = Vec::new();
    let mut output = None;
    // Set once an option only `kubectl logs` takes appears.
    let mut logs_only = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if !argument.starts_with('-') || argument == "-" {
            positionals.push(argument);
            index += 1;
            continue;
        }
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (argument, None),
        };
        if FLAGS.contains(&name) || logs::FLAGS.contains(&name) {
            if inline.is_some_and(|value| !matches!(value, "true" | "false")) {
                return false;
            }
            logs_only |= logs::FLAGS.contains(&name);
            index += 1;
            continue;
        }
        let (value, consumed) = match inline {
            Some(value) => (value, 1),
            None => match arguments.get(index + 1) {
                Some(value) => (value.as_str(), 2),
                None => return false,
            },
        };
        match logs::value_safe(name, value) {
            Some(safe) => {
                if !safe {
                    return false;
                }
                logs_only = true;
            }
            None => {
                if !option_value_safe(name, value, context) {
                    return false;
                }
            }
        }
        if matches!(name, "-o" | "--output") {
            output = Some(value);
        }
        index += consumed;
    }
    verb_safe(&positionals, output) && (!logs_only || positionals.first() == Some(&"logs"))
}

/// A whole `kubectl` segment, generic checks included, that the native proof
/// accepts as a read of non-secret cluster state. The compatibility layer uses
/// it so it does not treat the same query as a possible Secret read.
pub(crate) fn proven_read_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    segment.executable.as_deref() == Some("kubectl")
        && super::segment_proof::exact_safe_segment_with_context(model, segment, false, context)
}

/// `export KUBECONFIG=<path>` naming a kubeconfig that passes the same trust
/// check as `--kubeconfig`. Any other exported name can change how a later
/// proven command runs, so it keeps the normal review.
pub(super) fn safe_export_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    model.dialect == "posix"
        && segment.pipeline_index == 0
        && !segment.arguments.is_empty()
        && segment.arguments.iter().all(|argument| {
            argument
                .strip_prefix("KUBECONFIG=")
                .is_some_and(|path| trust::trusted_kubeconfig(path, context))
        })
}

/// `KUBECONFIG=<path> kubectl ...` selects a kubeconfig for that one command,
/// as `--kubeconfig <path>` does, so it passes the same trust check. Any other
/// setting, a wrapper, or a value list keeps the command reviewed.
pub(super) fn trusted_kubeconfig_prefix(
    segment: &crate::CommandSegmentV1,
    context: super::PathContext<'_>,
) -> bool {
    segment.environment_names == ["KUBECONFIG"]
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
        && matches!(
            segment.tokens.as_slice(),
            [setting, executable, arguments @ ..]
                if executable == "kubectl"
                    && arguments == segment.arguments.as_slice()
                    && setting
                        .strip_prefix("KUBECONFIG=")
                        .is_some_and(|path| trust::trusted_kubeconfig(path, context))
        )
}

fn option_value_safe(name: &str, value: &str, context: super::PathContext<'_>) -> bool {
    if value.is_empty() || value.starts_with('-') {
        return false;
    }
    match name {
        "--kubeconfig" => trust::trusted_kubeconfig(value, context),
        "-o" | "--output" => {
            let format = value.split_once('=').map_or(value, |(format, _)| format);
            OUTPUT_FORMATS.contains(&format)
        }
        _ => VALUE_OPTIONS.contains(&name),
    }
}

fn verb_safe(positionals: &[&str], output: Option<&str>) -> bool {
    let Some((verb, rest)) = positionals.split_first() else {
        return false;
    };
    if rest.iter().any(|token| names_secret(token)) {
        return false;
    }
    // ConfigMaps often hold credentials in practice, so only their names and
    // summary columns print without review.
    let config_data = rest.iter().any(|token| names_config_map(token))
        && (*verb == "describe" || output.is_some_and(|format| !SUMMARY_FORMATS.contains(&format)));
    if config_data {
        return false;
    }
    match *verb {
        "get" | "describe" | "explain" => !rest.is_empty(),
        "logs" => output.is_none() && logs::target_safe(rest),
        "top" => matches!(rest, [resource, ..] if TOP_RESOURCES.contains(resource)),
        "api-resources" | "api-versions" | "cluster-info" | "version" => rest.is_empty(),
        "config" => matches!(rest, ["get-contexts" | "current-context", ..] if rest.len() <= 2),
        // `kubectl rollout` groups a deployment's own writes with two reads of
        // the rollout it already has. `status` waits for the rollout named on
        // the command line and prints how far it got; `history` prints the
        // revisions recorded for it. Neither names a revision to move to, so
        // neither is a way to start, stop or undo a rollout -- `restart`,
        // `undo`, `pause` and `resume` are, and they stay out.
        //
        // Both read exactly one rollout, written either as `deploy/web` or as
        // the two words `deploy web`. A bare resource type selects every
        // deployment in the namespace instead of one, which is a different
        // read from the one the command appears to name, so it stays out
        // alongside a command that names two.
        "rollout" => {
            matches!(rest, ["status" | "history", target @ ..] if names_one_rollout(target))
        }
        // `kubectl wait` blocks until the objects named on the command line
        // reach the condition `--for` describes, or until its timeout, and
        // prints which ones did. Waiting is not a way to bring the condition
        // about, and unlike `logs --follow` it ends. `-f` reads a local
        // manifest and stays out with every other unlisted option.
        "wait" => !rest.is_empty(),
        _ => false,
    }
}

/// Whether `target` names exactly one rollout, as `deploy/web` or `deploy web`.
fn names_one_rollout(target: &[&str]) -> bool {
    match target {
        [slashed] => slashed
            .split_once('/')
            .is_some_and(|(resource, name)| !resource.is_empty() && !name.is_empty()),
        [resource, name] => !resource.is_empty() && !resource.contains('/') && !name.is_empty(),
        _ => false,
    }
}

fn resource_heads(token: &str) -> impl Iterator<Item = String> + '_ {
    token.split(',').map(|item| {
        let resource = item.split('/').next().unwrap_or("");
        resource
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
    })
}

fn names_secret(token: &str) -> bool {
    crate::sfrs_kubernetes_support::resource_token_includes_secret(token)
        || resource_heads(token).any(|head| head.starts_with("sealedsecret"))
}

fn names_config_map(token: &str) -> bool {
    resource_heads(token).any(|head| head == "cm" || head.starts_with("configmap"))
}

#[cfg(test)]
#[path = "kubectl_reads_tests.rs"]
mod tests;
