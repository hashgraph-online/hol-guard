//! Native discovery and one owner-only fixed-plan snapshot for bubblewrap.
use super::plan::{Result, DIRECTORY, FILENAME};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    profile_version: String,
    workspace: PathBuf,
    cwd: PathBuf,
    private_root: PathBuf,
    allowed_executables: Vec<PathBuf>,
    read_only_roots: Vec<PathBuf>,
    output_roots: Vec<PathBuf>,
    command: Vec<String>,
    backend_executable: PathBuf,
    backend: String,
    platform: String,
    search_path: String,
}

const ROOTS: &[&str] = &[
    "/lib",
    "/lib64",
    "/usr/lib",
    "/usr/lib64",
    "/usr/share",
    "/usr/local/lib",
];
const FILES: &[&str] = &[
    "/etc/hosts",
    "/etc/ld.so.cache",
    "/etc/nsswitch.conf",
    "/etc/protocols",
    "/etc/resolv.conf",
    "/etc/services",
];
const PROFILES: &[&str] = &[
    "pytest-readonly-v2",
    "node-test-readonly-v1",
    "vitest-readonly-v1",
    "git-readonly-v1",
    "node-tool-readonly-v1",
    "node-build-output-v1",
    "python-eval-readonly-v1",
    "node-eval-readonly-v1",
];

fn canonical(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .map_err(|_| "Linux runtime grant could not be resolved.")
}

fn native(operation: &str, input: &Value, deadline: Instant) -> Result<Value> {
    let result =
        guard_command::restricted_pytest::evaluate_with_deadline(operation, input, deadline);
    result
        .get("value")
        .cloned()
        .ok_or("Linux runtime evidence could not be admitted.")
}

fn index(
    root: &Path,
    indexed: &mut BTreeMap<PathBuf, (u64, u64)>,
    candidates: &mut super::paths::Candidates,
    deadline: Instant,
) -> Result<()> {
    let (grants, discovered) = super::paths::collect_with_candidates(root, 240_000, deadline)?;
    for (name, parents) in discovered {
        candidates.entry(name).or_default().extend(parents);
    }
    for (path, device, inode) in grants {
        indexed.insert(path, (device, inode));
    }
    Ok(())
}

pub(super) fn argv(value: &Value, deadline: Instant) -> Result<Value> {
    argv_with_system(value, ROOTS, FILES, deadline)
}

/// System grants are parameters so tests can replay the plan without indexing
/// the host's library trees; production always passes the fixed lists above.
pub(super) fn argv_with_system(
    value: &Value,
    roots: &[&str],
    fixed_files: &[&str],
    deadline: Instant,
) -> Result<Value> {
    let input: Input =
        serde_json::from_value(value.clone()).map_err(|_| "Unexpected Linux execution profile.")?;
    if input.platform != "linux"
        || input.backend != "linux-bubblewrap"
        || !PROFILES.contains(&input.profile_version.as_str())
        || input.command.is_empty()
        || input.command.len() > 4096
    {
        return Err("Unexpected Linux execution profile.");
    }
    let private = fs::symlink_metadata(&input.private_root)
        .map_err(|_| "Unsafe Linux private execution directory.")?;
    if !private.is_dir()
        || private.uid() != nix::unistd::getuid().as_raw()
        || private.mode() & 0o077 != 0
    {
        return Err("Unsafe Linux private execution directory.");
    }
    let helper = canonical(
        &std::env::current_exe().map_err(|_| "The packaged Linux boundary is unavailable.")?,
    )?;
    let mut images: BTreeSet<_> = input
        .allowed_executables
        .iter()
        .map(|p| canonical(p))
        .collect::<Result<_>>()?;
    let mut loaders = Vec::new();
    for image in &images {
        let mut prefix = [0u8; 4];
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(image)
            .map_err(|_| "Unverified Linux executable image.")?;
        file.read_exact(&mut prefix)
            .map_err(|_| "Unverified Linux executable image.")?;
        if &prefix == b"\x7fELF" {
            if let Some(loader) = super::elf::resolve(image)? {
                loaders.push(loader);
            }
        } else if !prefix.starts_with(b"#!") {
            return Err("Unverified Linux executable image.");
        }
    }
    images.extend(loaders);
    let system_roots: Vec<_> = roots
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .map(|p| canonical(&p))
        .collect::<Result<_>>()?;
    if system_roots.iter().any(|p| input.workspace.starts_with(p)) {
        return Err("Workspace overlaps a system runtime grant.");
    }
    let runtime_value = native(
        "runtime_roots",
        &json!({"allowed_executables":input.allowed_executables,
        "workspace":input.workspace,"private_root":input.private_root,"search_path":input.search_path}),
        deadline,
    )?;
    let runtime_roots: Vec<PathBuf> =
        serde_json::from_value(runtime_value).map_err(|_| "Invalid Linux runtime roots.")?;
    let mut mounts: Vec<_> = roots
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .chain(runtime_roots.iter().cloned())
        .chain([helper.clone()])
        .collect();
    let mut indexed = BTreeMap::new();
    let mut candidates = super::paths::Candidates::new();
    index(&input.workspace, &mut indexed, &mut candidates, deadline)?;
    let mut list_roots = vec![input.workspace.clone()];
    let mut discovery: Vec<_> = system_roots
        .iter()
        .chain(&runtime_roots)
        .chain(&input.read_only_roots)
        .map(|p| canonical(p))
        .collect::<Result<BTreeSet<_>>>()?
        .into_iter()
        .collect();
    discovery.sort_by_key(|p| (p.components().count(), p.clone()));
    let mut discovered: Vec<PathBuf> = Vec::new();
    for root in discovery {
        if root.starts_with(&input.workspace) || discovered.iter().any(|p| root.starts_with(p)) {
            continue;
        }
        index(&root, &mut indexed, &mut candidates, deadline)?;
        list_roots.push(root.clone());
        mounts.push(root.clone());
        discovered.push(root);
    }
    let mut files: Vec<_> = fixed_files
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
        .map(|p| canonical(&p))
        .collect::<Result<_>>()?;
    if input.profile_version.starts_with("node-") || input.profile_version.starts_with("vitest-") {
        let ssl = PathBuf::from("/etc/ssl/openssl.cnf");
        if ssl.is_file() && canonical(&ssl)? == ssl {
            let metadata =
                fs::metadata(&ssl).map_err(|_| "Untrusted system OpenSSL configuration.")?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err("Untrusted system OpenSSL configuration.");
            }
            files.push(ssl);
        }
    }
    for path in files {
        let metadata = fs::metadata(&path).map_err(|_| "Ambiguous Linux runtime read target.")?;
        if metadata.nlink() != 1 {
            return Err("Ambiguous Linux runtime read target.");
        }
        indexed.insert(path.clone(), (metadata.dev(), metadata.ino()));
        mounts.push(path);
    }
    for path in &input.output_roots {
        use std::os::unix::fs::DirBuilderExt;
        if !path.exists() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| "Linux output boundary unavailable.")?;
        }
    }
    let write_roots: Vec<_> = std::iter::once(input.private_root.clone())
        .chain(input.output_roots.iter().cloned())
        .collect();
    // In process and typed: the system index can hold hundreds of thousands
    // of paths, and a JSON round trip of it would spend the launch deadline.
    let mut records = guard_command::restricted_pytest::mapping_evidence(
        images.clone(),
        indexed.keys().cloned().collect(),
        runtime_roots.clone(),
        input.workspace.clone(),
        candidates,
        deadline,
    )
    .map_err(|_| "Linux runtime evidence could not be admitted.")?;
    for record in records
        .as_array_mut()
        .ok_or("Invalid executable mapping evidence.")?
    {
        let image = PathBuf::from(
            record["path"]
                .as_str()
                .ok_or("Invalid executable mapping path.")?,
        );
        let mut aliases = BTreeSet::from([image.clone()]);
        for destination in &mounts {
            let source = canonical(destination)?;
            if source.is_dir() && image.starts_with(&source) {
                aliases.insert(
                    destination.join(
                        image
                            .strip_prefix(&source)
                            .map_err(|_| "Invalid executable mapping path.")?,
                    ),
                );
            } else if source == image {
                aliases.insert(destination.clone());
            }
        }
        record["targets"] = json!(aliases);
    }
    let writes = write_roots
        .iter()
        .map(|p| {
            let m = fs::metadata(p).map_err(|_| "Linux output boundary unavailable.")?;
            Ok(json!([p, m.dev(), m.ino()]))
        })
        .collect::<Result<Vec<_>>>()?;
    let payload = json!({"schema":"guard-linux-readonly-plan.v2","mapping_records":records,"command":input.command,
        "read_roots":[],"read_files":indexed.keys().collect::<Vec<_>>(),"list_roots":list_roots,"write_roots":write_roots,
        "executables":images,"read_identities":indexed.iter().map(|(p,(d,i))|json!([p,d,i])).collect::<Vec<_>>(),
        "write_identities":writes,"device_files":["/dev/null","/dev/random","/dev/urandom"]});
    let raw =
        serde_json::to_vec(&payload).map_err(|_| "Linux execution plan could not be encoded.")?;
    let _validated = super::plan::parse(payload)?;
    if raw.len() as u64 > super::plan::MAX_BYTES || Instant::now() >= deadline {
        return Err("Linux execution plan exceeds its budget.");
    }
    let digest = format!("{:x}", Sha256::digest(&raw));
    super::index_snapshot::check(deadline)?;
    let snapshot = input.private_root.join(FILENAME);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&snapshot)
        .map_err(|_| "Linux execution snapshot could not be created.")?;
    super::index_snapshot::write_bytes(&mut file, &raw, deadline)?;
    let result = super::argv::compose(
        &input.backend_executable,
        &input.workspace,
        &input.cwd,
        &helper,
        mounts,
        write_roots,
        images,
        &snapshot,
        &digest,
        DIRECTORY,
    )?;
    super::index_snapshot::check(deadline)?;
    Ok(result)
}
