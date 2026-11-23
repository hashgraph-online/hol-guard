use std::path::Path;

/// The name Windows opens for a path component. Win32 drops trailing dots and
/// spaces, and `name::$DATA` is the file's default stream, so `.env.`,
/// `id_rsa ` and `.env::$DATA` all open the same file as the plain name.
/// Win32 trims the path before NTFS parses the stream, so `.env::$DATA.`
/// also opens `.env`. A name of only dots and spaces (`..`, the redacted
/// `...`) is kept as is.
pub fn win32_name(part: &str) -> &str {
    let trimmed = part.trim_end_matches(['.', ' ']);
    let stripped = match trimmed.len().checked_sub(7) {
        Some(at)
            if trimmed.is_char_boundary(at) && trimmed[at..].eq_ignore_ascii_case("::$data") =>
        {
            &trimmed[..at]
        }
        _ => trimmed,
    };
    match stripped.trim_end_matches(['.', ' ']) {
        "" => part,
        name => name,
    }
}

/// Whether a name carries the `private-key` or `wallet-key` marker anywhere
/// in it. A key container is usually named exactly that (`private.key`,
/// `wallet.key`) or carries a key extension, both of which are read above;
/// this is the catch-all for a name that spells the marker out, such as
/// `prod-private-key-backup`.
pub fn wallet_key_named(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["private-key", "private_key", "wallet-key", "wallet_key"]
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Extensions the tracked-document proof can read a file back under:
/// `search_scope_tracked` accepts exactly these, reads the committed file and
/// scans it for credential-shaped values.
///
/// A file in one of them whose name only spells the marker out is a project
/// document about keys rather than a key. `private_key_jwt` is an OpenID
/// Connect client authentication method, so a design note named
/// `private-key-jwt-client-auth.md` describes a feature the way
/// `command.kubernetes-secrets.json` does. Such a name keeps the review its
/// words earn through `credential_named_path`, where the committed-document
/// proof can clear it, instead of the container family, which has no relief
/// at all and refused every read of the file and every recursive search of
/// the directory holding it.
///
/// A key container carries no extension, or a key or certificate extension,
/// both of which are read above, and a hidden name is refused on the dot
/// alone, so neither reaches this.
const PROVABLE_DOCUMENT_EXTENSIONS: &[&str] = &["json", "md", "toml", "yaml", "yml"];

fn provable_document_name(basename: &str) -> bool {
    !basename.starts_with('.')
        && basename.rsplit_once('.').is_some_and(|(stem, extension)| {
            !stem.is_empty() && PROVABLE_DOCUMENT_EXTENSIONS.contains(&extension)
        })
}

pub fn sensitive_path_family(path: &Path) -> Option<(&'static str, &'static str)> {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts: Vec<&str> = normalized
        .split('/')
        .map(win32_name)
        .filter(|part| !part.is_empty())
        .collect();
    let basename = parts.last().copied().unwrap_or_default();
    if basename == ".env" || basename.starts_with(".env.") {
        return Some(("local .env file", "critical"));
    }
    // Cloudflare Wrangler reads a worker's local secrets from `.dev.vars`
    // beside its sources, and `.dev.vars.<environment>` per environment.
    if basename == ".dev.vars" || basename.starts_with(".dev.vars.") {
        return Some(("Wrangler local secrets file", "high"));
    }
    if basename.ends_with(".key") {
        return Some(("private-key file", "critical"));
    }
    if basename.starts_with("krb5cc_") {
        return Some(("Kerberos credential cache", "high"));
    }
    let direct = [
        (".envrc", "environment setup credentials", "high"),
        (".authrc", "authentication credentials", "high"),
        (".npmrc", "npm registry credentials", "high"),
        (".pypirc", "Python package credentials", "high"),
        (".netrc", "netrc credentials", "high"),
        (".git-credentials", "Git credential store", "high"),
        (".terraform.tfvars", "Terraform variable secrets", "high"),
        ("terraform.tfvars", "Terraform variable secrets", "high"),
        ("private-key.pem", "wallet/private-key file", "critical"),
        ("private.key", "wallet/private-key file", "critical"),
        ("wallet.key", "wallet/private-key file", "critical"),
    ];
    if let Some((_, family, sensitivity)) = direct.iter().find(|(name, _, _)| *name == basename) {
        return Some((*family, *sensitivity));
    }
    if wallet_key_named(basename) && !provable_document_name(basename) {
        return Some(("wallet/private-key file", "critical"));
    }
    if parts
        .windows(2)
        .any(|window| window == [".aws", "credentials"])
    {
        return Some(("AWS shared credentials file", "high"));
    }
    if parts.windows(2).any(|window| window == [".aws", "config"]) {
        return Some(("AWS shared config file", "high"));
    }
    if parts
        .windows(2)
        .any(|window| window == [".docker", "config.json"])
    {
        return Some(("Docker client config", "high"));
    }
    if parts.windows(2).any(|window| window == [".kube", "config"]) {
        return Some(("Kubernetes config", "high"));
    }
    if parts.contains(&".gnupg") {
        return Some(("GnuPG key material", "high"));
    }
    if let Some(index) = parts.iter().position(|part| *part == ".ssh") {
        if parts
            .get(index + 1)
            .is_some_and(|name| matches!(*name, "id_rsa" | "id_ed25519" | "id_ecdsa"))
        {
            return Some(("SSH private key", "critical"));
        }
        if parts.get(index + 1).is_some_and(|name| *name == "config") {
            return Some(("SSH client config", "high"));
        }
    }
    None
}

#[cfg(test)]
#[path = "sensitive_path_family_tests.rs"]
mod tests;
