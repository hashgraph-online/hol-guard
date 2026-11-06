//! Credential paths withheld by every contained-execution backend.

fn literal(value: &str) -> String {
    let mut result = String::new();
    for c in value.chars() {
        if c.is_ascii_alphabetic() {
            result.push_str(&format!(
                "[{}{}]",
                c.to_ascii_lowercase(),
                c.to_ascii_uppercase()
            ));
        } else {
            if matches!(c, '.' | '-') {
                result.push('\\');
            }
            result.push(c);
        }
    }
    result
}

fn alternatives(names: &[&str]) -> String {
    names
        .iter()
        .map(|v| literal(v))
        .collect::<Vec<_>>()
        .join("|")
}

/// Credential-bearing paths; each regex matches a `/`-separated path, absolute
/// or relative to the workspace root. Letters match either case.
pub fn patterns() -> Vec<String> {
    vec![
        format!("(^|/){}($|[./])", literal(".env")),
        format!("(^|/)[^/]*{}$", literal(".key")),
        format!("(^|/){}[^/]*$", literal("krb5cc_")),
        format!(
            "(^|/)({})$",
            alternatives(&[
                ".envrc",
                ".authrc",
                ".npmrc",
                ".pypirc",
                ".netrc",
                ".git-credentials",
                "terraform.tfvars",
                "private.key",
                "wallet.key"
            ])
        ),
        format!(
            "(^|/)[^/]*({})[^/]*$",
            alternatives(&["private-key", "private_key", "wallet-key", "wallet_key"])
        ),
        format!(
            "(^|/)({})(/|$)",
            alternatives(&[".ssh", ".aws", ".docker", ".kube", ".gnupg", ".hol-guard"])
        ),
    ]
}
