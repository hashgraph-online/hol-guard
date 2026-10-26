//! Secret-bearing path classification for hook action redaction.

const SECRET_SUFFIXES: &[(&[&str], &str)] = &[
    (&[".aws", "credentials"], "AWS shared credentials file"),
    (&[".aws", "config"], "AWS shared config file"),
    (&[".docker", "config.json"], "Docker client config"),
    (&[".kube", "config"], "Kubernetes config"),
    (&[".ssh", "id_rsa"], "SSH private key"),
    (&[".ssh", "id_ed25519"], "SSH private key"),
    (&[".ssh", "id_ecdsa"], "SSH private key"),
    (&[".ssh", "config"], "SSH client config"),
];
const SECRET_DIRECTORIES: &[&str] = &[".gnupg"];

/// `redacted_secret_path_context(path)`.
pub fn redacted_secret_path_context(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let segments: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let lowered: Vec<String> = segments.iter().map(|part| part.to_lowercase()).collect();
    if lowered.is_empty() {
        return None;
    }
    for (suffix, _label) in SECRET_SUFFIXES {
        if lowered.len() >= suffix.len()
            && lowered[lowered.len() - suffix.len()..]
                .iter()
                .zip(*suffix)
                .all(|(left, right)| left == right)
        {
            return Some(format!(".../{}", suffix.join("/")));
        }
    }
    for directory in SECRET_DIRECTORIES {
        if lowered.iter().any(|segment| segment == directory) && segments.len() > 1 {
            return Some(format!(".../{directory}/{}", segments[segments.len() - 1]));
        }
    }
    None
}
