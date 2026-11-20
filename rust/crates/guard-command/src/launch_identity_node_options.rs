//! The part of a node-script launch's `NODE_OPTIONS` that binds an approval.
//!
//! Inert flags (`guard_contracts::node_options_inert`) are left out, a short
//! list of behaviour-only flags is bound by value, and anything else leaves
//! the launch unproven.

/// `NODE_OPTIONS` flags that neither load code nor read or write a file but
/// still change how Node behaves. They are bound into the entrypoint identity
/// by value, so an approval given under one value is not reused under another.
const NODE_OPTIONS_BOUND_FLAGS: &[&str] = &[
    "--abort-on-uncaught-exception",
    "--disallow-code-generation-from-strings",
    "--jitless",
    "--no-addons",
    "--no-experimental-fetch",
    "--no-experimental-global-navigator",
    "--no-experimental-websocket",
    "--no-network-family-autoselection",
    "--openssl-legacy-provider",
    "--pending-deprecation",
    "--throw-deprecation",
    "--tls-max-v1.2",
    "--tls-max-v1.3",
    "--tls-min-v1.0",
    "--tls-min-v1.1",
    "--tls-min-v1.2",
    "--tls-min-v1.3",
    "--use-bundled-ca",
    "--use-openssl-ca",
    "--use-system-ca",
    "--zero-fill-buffers",
];

fn node_option_digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 12 && value.bytes().all(|b| b.is_ascii_digit())
}

fn node_option_warning_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn node_option_dns_order(value: &str) -> bool {
    matches!(value, "ipv4first" | "ipv6first" | "verbatim")
}

fn node_option_rejection_mode(value: &str) -> bool {
    matches!(
        value,
        "none" | "strict" | "throw" | "warn" | "warn-with-error-code"
    )
}

/// A valued flag's name and the check its value has to pass.
type BoundNodeOption = (&'static str, fn(&str) -> bool);

/// Valued `NODE_OPTIONS` flags bound the same way, with the values accepted.
const NODE_OPTIONS_BOUND_VALUES: &[BoundNodeOption] = &[
    ("--disable-warning", node_option_warning_code),
    ("--dns-result-order", node_option_dns_order),
    ("--max-http-header-size", node_option_digits),
    (
        "--network-family-autoselection-attempt-timeout",
        node_option_digits,
    ),
    ("--stack-size", node_option_digits),
    ("--unhandled-rejections", node_option_rejection_mode),
];

/// The part of a `NODE_OPTIONS` value that has to match for a launch to
/// reuse an approval: the bound flags in the order given, with inert flags
/// left out. `None` when any token could load code, read or write a file, or
/// is not recognised. Splits on spaces only, as `node_options_inert` does, so
/// quoting or a tab leaves a token unrecognised rather than reinterpreted.
pub(super) fn launch_binding(value: &str) -> Option<Vec<String>> {
    let mut bound = Vec::new();
    let mut tokens = value.split(' ').filter(|token| !token.is_empty());
    while let Some(token) = tokens.next() {
        if guard_contracts::node_options_inert(token) {
            continue;
        }
        let (raw_name, inline_value) = match token.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (token, None),
        };
        if !raw_name.starts_with("--") {
            return None;
        }
        let name = format!("--{}", raw_name[2..].replace('_', "-"));
        if inline_value.is_none() && NODE_OPTIONS_BOUND_FLAGS.contains(&name.as_str()) {
            bound.push(name);
            continue;
        }
        let (_, accepts) = NODE_OPTIONS_BOUND_VALUES
            .iter()
            .find(|(flag, _)| *flag == name)?;
        let option_value = match inline_value {
            Some(value) => value,
            None => tokens.next()?,
        };
        if !accepts(option_value) {
            return None;
        }
        bound.push(format!("{name}={option_value}"));
    }
    Some(bound)
}
