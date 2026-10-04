use std::path::Path;

pub fn sensitive_path_family(path: &Path) -> Option<(&'static str, &'static str)> {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let basename = parts.last().copied().unwrap_or_default();
    if basename == ".env" || basename.starts_with(".env.") {
        return Some(("local .env file", "critical"));
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
        ("terraform.tfvars", "Terraform variable secrets", "high"),
        ("private-key.pem", "wallet/private-key file", "critical"),
        ("private.key", "wallet/private-key file", "critical"),
        ("wallet.key", "wallet/private-key file", "critical"),
    ];
    if let Some((_, family, sensitivity)) = direct.iter().find(|(name, _, _)| *name == basename) {
        return Some((*family, *sensitivity));
    }
    if basename.contains("private-key")
        || basename.contains("private_key")
        || basename.contains("wallet-key")
        || basename.contains("wallet_key")
    {
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
