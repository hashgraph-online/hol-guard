//! Trust for a kubeconfig named on the command line or in `KUBECONFIG`.
//!
//! A kubeconfig can run a credential plugin (`exec`, `auth-provider`) and make
//! `kubectl` read local files and send them to the server it names
//! (`tokenFile`, client certificates and keys). One that carries none of
//! those fields only selects a server, so it is accepted wherever it lives.
//! One that does is accepted only from a location the agent's working tree
//! cannot supply: not below the working directory, not inside any Git
//! checkout, not in a temporary directory, and not writable by other users.

use std::fs;
use std::path::Path;

const MAX_KUBECONFIG_BYTES: u64 = 1024 * 1024;

/// Field names that run code, read local credential files, or route traffic.
const ACTIVE_TERMS: [&str; 9] = [
    "exec",
    "auth-provider",
    "cmd-path",
    "token",
    "password",
    "client-key",
    "client-certificate",
    "proxy-url",
    "as-user-extra",
];

pub(super) fn trusted_kubeconfig(value: &str, context: crate::pretool::PathContext<'_>) -> bool {
    if value.is_empty() || value.contains([':', ';', '$', '`', '~', '\n', '\r']) {
        return false;
    }
    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(cwd) = context.cwd {
        Path::new(cwd).join(path)
    } else {
        return false;
    };
    let Ok(canonical) = fs::canonicalize(&path) else {
        return false;
    };
    let Ok(metadata) = fs::metadata(&canonical) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() > MAX_KUBECONFIG_BYTES {
        return false;
    }
    let Ok(text) = fs::read_to_string(&canonical) else {
        return false;
    };
    let lowered = text.to_ascii_lowercase();
    if !ACTIVE_TERMS.iter().any(|term| lowered.contains(term)) {
        return true;
    }
    outside_agent_trees(&canonical, &metadata, context)
}

fn outside_agent_trees(
    path: &Path,
    metadata: &fs::Metadata,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    let Some(cwd) = context.cwd.filter(|cwd| !cwd.is_empty()) else {
        return false;
    };
    let canonical_cwd = fs::canonicalize(cwd).ok();
    if path.starts_with(cwd)
        || canonical_cwd
            .as_ref()
            .is_some_and(|directory| path.starts_with(directory))
        || crate::pretool::trusted_location::temporary_location(path)
        || path
            .ancestors()
            .skip(1)
            .any(|ancestor| ancestor.join(".git").exists())
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o022 != 0 {
            return false;
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    true
}
