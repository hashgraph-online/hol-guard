//! Native OS policy construction for a contained launch plan.
use super::authority::{ancestor_paths, dedupe_parent_paths, runtime_roots};
use super::credentials::{denials, patterns, seatbelt_string};
use super::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    profile_version: String,
    workspace: PathBuf,
    cwd: PathBuf,
    private_root: PathBuf,
    allowed_executables: Vec<PathBuf>,
    read_only_roots: Vec<PathBuf>,
    output_roots: Vec<PathBuf>,
    exec_roots: Vec<PathBuf>,
    write_denials: Vec<PathBuf>,
    command: Vec<String>,
    backend_executable: PathBuf,
    user_site_root: Option<PathBuf>,
    linked_git: Option<super::workspace_linked::LinkedGit>,
    #[serde(rename = "search_path")]
    _search_path: String,
    /// `workspace-contained-grant-v1` only: the plan's grant capabilities.
    capabilities: Vec<String>,
    /// `workspace-contained-grant-v1` only: the home a state directory must
    /// sit in; without it no state capability composes.
    home: Option<PathBuf>,
}

#[cfg(test)]
#[path = "workspace_grant_profile_tests.rs"]
mod workspace_grant_profile_tests;
#[path = "workspace_profile.rs"]
pub(super) mod workspace_profile;
#[cfg(test)]
#[path = "workspace_profile_loopback_tests.rs"]
mod workspace_profile_loopback_tests;
#[cfg(test)]
#[path = "workspace_profile_tests.rs"]
mod workspace_profile_tests;

pub(super) const WORKSPACE_CONTAINED_PROFILE: &str = "workspace-contained-v1";
const READONLY: &[&str] = &[
    "pytest-readonly-v2",
    "node-test-readonly-v1",
    "vitest-readonly-v1",
    "git-readonly-v1",
    "node-tool-readonly-v1",
    "node-build-output-v1",
    "python-eval-readonly-v1",
    "node-eval-readonly-v1",
];
const MAC_ROOTS: &[&str] = &[
    "/System",
    "/Library/Apple",
    "/Library/Frameworks",
    "/opt/homebrew/Cellar",
    "/opt/homebrew/opt",
    "/usr/lib",
    "/usr/local/Cellar",
    "/usr/local/opt",
    "/usr/share",
];
const MAC_FILES: &[&str] = &[
    "/dev/null",
    "/dev/random",
    "/dev/urandom",
    "/private/etc/hosts",
    "/private/etc/protocols",
    "/private/etc/resolv.conf",
    "/private/etc/services",
];
const LINUX_ROOTS: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/share",
    "/usr/local/lib",
];
const LINUX_FILES: &[&str] = &[
    "/etc/hosts",
    "/etc/ld.so.cache",
    "/etc/nsswitch.conf",
    "/etc/protocols",
    "/etc/resolv.conf",
    "/etc/services",
];

fn filter(paths: &[PathBuf], kind: &str) -> String {
    paths
        .iter()
        .map(|p| format!("({kind} {})", seatbelt_string(&p.to_string_lossy())))
        .collect::<Vec<_>>()
        .join(" ")
}

fn existing(paths: &[&str]) -> Vec<PathBuf> {
    paths
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

fn collection_link_metadata(input: &Input) -> Result<Vec<PathBuf>, RestrictedPytestError> {
    let patterns: Vec<Regex> = patterns().iter().map(|p| Regex::new(p).unwrap()).collect();
    let mut targets = BTreeSet::new();
    for directory in BTreeSet::from([input.workspace.clone(), input.cwd.clone()]) {
        let entries = fs::read_dir(directory).map_err(|_| {
            RestrictedPytestError::new(
                PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
                "Collection metadata is unavailable.",
            )
        })?;
        for entry in entries.take(4096) {
            let entry = entry.map_err(|_| {
                RestrictedPytestError::new(
                    PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
                    "Collection metadata is unavailable.",
                )
            })?;
            if entry.file_type().is_ok_and(|v| v.is_symlink()) {
                if let Ok(target) = entry.path().canonicalize() {
                    if !patterns
                        .iter()
                        .any(|p| p.is_match(&target.to_string_lossy()))
                    {
                        targets.insert(target);
                    }
                }
            }
        }
    }
    Ok(targets.into_iter().collect())
}

fn macos_profile(input: &Input) -> Result<String, RestrictedPytestError> {
    // Capabilities widen only the grant profile; on any other they are refused.
    if !input.capabilities.is_empty()
        && input.profile_version != super::workspace_grant::GRANT_PROFILE
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Invalid restricted execution request.",
        ));
    }
    if input.profile_version == WORKSPACE_CONTAINED_PROFILE {
        return workspace_profile::compose(input, &existing(MAC_ROOTS), &existing(MAC_FILES));
    }
    if input.profile_version == super::workspace_grant::GRANT_PROFILE {
        let rules = super::workspace_grant::rules(
            &input.capabilities,
            &input.read_only_roots,
            input.home.as_deref(),
        )?;
        return workspace_profile::compose_with(
            input,
            &existing(MAC_ROOTS),
            &existing(MAC_FILES),
            &rules,
        );
    }
    let mut files = existing(MAC_FILES);
    if matches!(
        input.profile_version.as_str(),
        "node-test-readonly-v1"
            | "vitest-readonly-v1"
            | "node-tool-readonly-v1"
            | "node-build-output-v1"
            | "node-eval-readonly-v1"
    ) {
        files.extend(
            [
                "/opt/homebrew/etc/openssl@3/openssl.cnf",
                "/usr/local/etc/openssl@3/openssl.cnf",
            ]
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.is_file()),
        );
    }
    compose_macos_profile(input, &existing(MAC_ROOTS), &files)
}

fn compose_macos_profile(
    input: &Input,
    system_roots: &[PathBuf],
    files: &[PathBuf],
) -> Result<String, RestrictedPytestError> {
    let mut roots = vec![input.workspace.clone(), input.private_root.clone()];
    roots.extend_from_slice(&input.read_only_roots);
    roots.extend_from_slice(system_roots);
    if let Some(root) = &input.user_site_root {
        if !super::user_site::grantable(root) {
            return Err(RestrictedPytestError::new(
                PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
                "Unexpected user site grant.",
            ));
        }
        roots.push(root.clone());
    }
    roots.extend(runtime_roots(
        &input.allowed_executables,
        &input.workspace,
        Some(&input.private_root),
    ));
    let targets = if input.profile_version == "pytest-readonly-v2" {
        collection_link_metadata(input)?
    } else {
        vec![]
    };
    let mut ancestors = roots.clone();
    ancestors.extend_from_slice(&input.allowed_executables);
    ancestors.extend_from_slice(&targets);
    let mut metadata = vec![PathBuf::from("/")];
    metadata.extend(targets);
    metadata.extend(ancestor_paths(&ancestors));
    let readonly = READONLY.contains(&input.profile_version.as_str());
    let mut writes = if readonly {
        vec![]
    } else {
        vec![input.workspace.clone()]
    };
    writes.extend_from_slice(&input.output_roots);
    writes.push(input.private_root.clone());
    let immutable: Vec<PathBuf> = input
        .allowed_executables
        .iter()
        .filter(|p| !path_is_within(p, &input.workspace))
        .cloned()
        .collect();
    let mut lines = vec![
        "(version 1)".to_owned(),
        "(deny default)".to_owned(),
        "(deny file-link)".to_owned(),
        "(allow process-fork)".to_owned(),
        format!(
            "(allow process-exec {})",
            filter(&input.allowed_executables, "literal")
        ),
        "(allow signal (target self) (target children))".to_owned(),
        "(allow sysctl-read)".to_owned(),
        "(allow file-read-data (literal \"/\"))".to_owned(),
        format!(
            "(allow file-read-metadata {})",
            filter(&metadata, "literal")
        ),
        format!(
            "(allow file-read* {} {})",
            filter(&roots, "subpath"),
            filter(files, "literal")
        ),
        format!(
            "(allow file-write* {} (literal \"/dev/null\"))",
            filter(&writes, "subpath")
        ),
    ];
    if !immutable.is_empty() {
        lines.push(format!(
            "(deny file-write* {})",
            filter(&immutable, "literal")
        ));
    }
    if readonly {
        lines.extend(denials(matches!(
            input.profile_version.as_str(),
            "vitest-readonly-v1" | "node-build-output-v1"
        )));
    }
    Ok(lines.join("\n"))
}

#[cfg(test)]
pub(super) fn replay_profile(input: &Value, grants: &Value) -> Value {
    let input: Input = serde_json::from_value(input.clone()).unwrap();
    let roots: Vec<PathBuf> = serde_json::from_value(grants["roots"].clone()).unwrap();
    let files: Vec<PathBuf> = serde_json::from_value(grants["files"].clone()).unwrap();
    json!({"value":compose_macos_profile(&input,&roots,&files).unwrap()})
}

fn bubblewrap_argv(input: &Input) -> Result<Vec<String>, RestrictedPytestError> {
    // A non-read-only profile gets a writable workspace here, which would drop
    // this profile's protected paths. Linux containment is a separate change.
    if input.profile_version == WORKSPACE_CONTAINED_PROFILE
        || input.profile_version == super::workspace_grant::GRANT_PROFILE
        || !input.capabilities.is_empty()
    {
        return Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "The workspace sandbox profile is not available on Linux.",
        ));
    }
    if READONLY.contains(&input.profile_version.as_str()) {
        return Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "Read-only Linux namespace requires its mapping authority.",
        ));
    }
    let mut argv = vec![input.backend_executable.to_string_lossy().into_owned()];
    argv.extend(
        [
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-net",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        .map(str::to_owned),
    );
    let mut roots = existing(LINUX_ROOTS);
    roots.extend(existing(LINUX_FILES));
    roots.extend(runtime_roots(
        &input.allowed_executables,
        &input.workspace,
        Some(&input.private_root),
    ));
    roots.extend(
        input
            .allowed_executables
            .iter()
            .filter(|p| !path_is_within(p, &input.workspace))
            .cloned(),
    );
    let workspace = input.workspace.to_string_lossy().into_owned();
    let private = input.private_root.to_string_lossy().into_owned();
    argv.extend([
        "--bind".to_owned(),
        workspace.clone(),
        workspace,
        "--dir".to_owned(),
        private.clone(),
        "--bind".to_owned(),
        private.clone(),
        private,
    ]);
    for root in dedupe_parent_paths(&roots) {
        let root = root.to_string_lossy().into_owned();
        argv.extend(["--ro-bind".to_owned(), root.clone(), root]);
    }
    argv.extend([
        "--chdir".to_owned(),
        input.cwd.to_string_lossy().into_owned(),
        "--".to_owned(),
    ]);
    argv.extend_from_slice(&input.command);
    Ok(argv)
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    if !matches!(
        operation,
        "macos_profile" | "collection_link_metadata" | "bubblewrap_argv"
    ) {
        return None;
    }
    let result = serde_json::from_value::<Input>(input.clone())
        .map_err(|_| {
            RestrictedPytestError::new(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Invalid restricted execution request.",
            )
        })
        .and_then(|input| match operation {
            "macos_profile" => macos_profile(&input).map(|v| json!(v)),
            "collection_link_metadata" => collection_link_metadata(&input).map(|v| json!(v)),
            "bubblewrap_argv" => bubblewrap_argv(&input).map(|v| json!(v)),
            _ => unreachable!(),
        });
    Some(match result {
        Ok(value) => json!({"value":value}),
        Err(error) => crate::restricted_command::error_reply(error),
    })
}
