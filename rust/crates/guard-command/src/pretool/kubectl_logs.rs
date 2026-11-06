//! `kubectl logs` of one pod or workload, bounded by time, line or byte
//! limits. It prints container output and changes nothing in the cluster, so
//! it joins `get` and `describe` as a read. Only a pod name or a
//! `<workload>/<name>` target is admitted, with an optional container name;
//! `--follow` never ends and stays out, and every option outside the lists
//! below keeps the review like any other unknown `kubectl` option.

/// `logs` options that take no value.
pub(super) const FLAGS: [&str; 6] = [
    "--all-containers",
    "--ignore-errors",
    "--prefix",
    "--previous",
    "-p",
    "--timestamps",
];

/// Workload kinds `kubectl logs <kind>/<name>` resolves to a pod.
const WORKLOADS: [&str; 20] = [
    "po",
    "pod",
    "pods",
    "deploy",
    "deployment",
    "deployments",
    "rs",
    "replicaset",
    "replicasets",
    "sts",
    "statefulset",
    "statefulsets",
    "ds",
    "daemonset",
    "daemonsets",
    "job",
    "jobs",
    "svc",
    "service",
    "services",
];

/// Whether `name` is a `logs` option with a value, and if so whether that
/// value is a plain count, duration, timestamp or container name.
pub(super) fn value_safe(name: &str, value: &str) -> Option<bool> {
    let safe = match name {
        "--tail" | "--limit-bytes" | "--max-log-requests" => value.parse::<u64>().is_ok(),
        "--since" | "--pod-running-timeout" => {
            bounded(value)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        }
        "--since-time" => {
            bounded(value)
                && value.bytes().all(|byte| {
                    byte.is_ascii_digit() || matches!(byte, b'T' | b'Z' | b':' | b'-' | b'+' | b'.')
                })
        }
        "-c" | "--container" => object_name(value),
        _ => return None,
    };
    Some(safe)
}

/// The positionals after `logs`: nothing (a `-l` selector picks the pods),
/// a pod or `<workload>/<name>`, and optionally a container name.
pub(super) fn target_safe(rest: &[&str]) -> bool {
    match rest {
        [] => true,
        [target] => target_named(target),
        [target, container] => target_named(target) && object_name(container),
        _ => false,
    }
}

fn target_named(token: &str) -> bool {
    match token.split_once('/') {
        Some((kind, name)) => {
            WORKLOADS.contains(&kind.to_ascii_lowercase().as_str()) && object_name(name)
        }
        None => object_name(token),
    }
}

fn bounded(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && !value.starts_with('-')
}

/// A Kubernetes object name: lowercase letters, digits, `-` and `.`.
fn object_name(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 253
        && !token.starts_with(['-', '.'])
        && token.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
}
