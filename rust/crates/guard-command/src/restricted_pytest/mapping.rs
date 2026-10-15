//! Inode-pinned, hashed dependency closure with one request deadline.
use super::mapping_elf;
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{Metadata, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::time::Instant;

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Input {
    images: BTreeSet<PathBuf>,
    read_files: BTreeSet<PathBuf>,
    runtime_roots: Vec<PathBuf>,
    workspace: PathBuf,
    dependency_candidates: Option<BTreeMap<String, BTreeSet<PathBuf>>>,
    path: PathBuf,
    library: bool,
    system_library: bool,
    #[serde(rename = "search_path")]
    _search_path: String,
    max_file_bytes: u64,
    max_mapping_bytes: u64,
}
impl Default for Input {
    fn default() -> Self {
        Self {
            images: BTreeSet::new(),
            read_files: BTreeSet::new(),
            runtime_roots: vec![],
            workspace: PathBuf::new(),
            dependency_candidates: None,
            path: PathBuf::new(),
            library: false,
            system_library: false,
            _search_path: String::new(),
            max_file_bytes: 256 * 1024 * 1024,
            max_mapping_bytes: 1024 * 1024 * 1024,
        }
    }
}
type Result<T> = std::result::Result<T, &'static str>;

fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err("Linux executable mapping inspection deadline exceeded.")
    } else {
        Ok(())
    }
}
fn identity(m: &Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
        m.mode()
    ])
}

struct Inspector<'a> {
    input: &'a Input,
    deadline: Instant,
    cache: BTreeMap<PathBuf, (Value, Vec<String>)>,
    total: u64,
    parents: BTreeSet<PathBuf>,
}
impl Inspector<'_> {
    fn inspect(&mut self, path: &Path) -> Result<(Value, Vec<String>)> {
        check(self.deadline)?;
        if let Some(value) = self.cache.get(path) {
            return Ok(value.clone());
        }
        if self.cache.len() >= 1024 {
            return Err("Too many executable mappings.");
        }
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "Invalid executable mapping file.")?;
        let before = file
            .metadata()
            .map_err(|_| "Invalid executable mapping file.")?;
        if !before.is_file()
            || before.len() == 0
            || before.len() > self.input.max_file_bytes.min(256 * 1024 * 1024)
        {
            return Err("Invalid executable mapping file.");
        }
        let mut prefix = [0; 4];
        let read = file
            .read(&mut prefix)
            .map_err(|_| "Invalid executable mapping file.")?;
        let library = !self.input.images.contains(path);
        let dependencies = if read == 4 && prefix == *b"\x7fELF" {
            let system = ["/usr/lib", "/usr/lib64", "/lib", "/lib64"]
                .iter()
                .any(|p| path.starts_with(p));
            mapping_elf::inspect(&mut file, &before, library, system, self.deadline)
                .map_err(|message| {
                    if message == "Linux executable mapping inspection deadline exceeded." {
                        message
                    } else {
                        "Unverified executable mapping."
                    }
                })?
                .1
        } else if !library && read >= 2 && prefix[..2] == *b"#!" {
            vec![]
        } else {
            return Err("Unverified executable mapping.");
        };
        self.total = self
            .total
            .checked_add(before.len())
            .ok_or("Executable mapping memory budget exceeded.")?;
        if self.total > self.input.max_mapping_bytes.min(1024 * 1024 * 1024) {
            return Err("Executable mapping memory budget exceeded.");
        }
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))
            .map_err(|_| "Invalid executable mapping file.")?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut count = 0u64;
        loop {
            check(self.deadline)?;
            let size = file
                .read(&mut buffer)
                .map_err(|_| "Invalid executable mapping file.")?;
            if size == 0 {
                break;
            }
            count += size as u64;
            if count > before.len() {
                return Err("Executable mapping changed during inspection.");
            }
            hasher.update(&buffer[..size]);
        }
        let after = file
            .metadata()
            .map_err(|_| "Executable mapping changed during inspection.")?;
        if identity(&before) != identity(&after) {
            return Err("Executable mapping changed during inspection.");
        }
        let record = json!({"path":path,"identity":identity(&before),"sha256":format!("{:x}",hasher.finalize())});
        self.cache
            .insert(path.to_path_buf(), (record.clone(), dependencies.clone()));
        Ok((record, dependencies))
    }
    fn closure(&mut self, seeds: Vec<PathBuf>) -> Result<BTreeMap<PathBuf, Value>> {
        let mut pending = seeds;
        let mut records = BTreeMap::new();
        while let Some(path) = pending.pop() {
            check(self.deadline)?;
            if records.contains_key(&path) {
                continue;
            }
            let (record, dependencies) = self.inspect(&path)?;
            records.insert(path, record);
            for name in dependencies {
                let mut matches = BTreeSet::new();
                // Discovery records filenames, including symlink aliases, without
                // granting reads through them. Restrict lookup to observed names,
                // then apply the same canonical target and read-index checks.
                // Legacy callers and path-valued DT_NEEDED retain full lookup.
                let parents: Vec<_> = match &self.input.dependency_candidates {
                    Some(index) if !name.contains('/') => index
                        .get(&name)
                        .into_iter()
                        .flatten()
                        .filter(|parent| self.parents.contains(*parent))
                        .collect(),
                    _ => self.parents.iter().collect(),
                };
                for parent in parents {
                    check(self.deadline)?;
                    if let Ok(candidate) = parent.join(&name).canonicalize() {
                        if self.input.read_files.contains(&candidate)
                            || self.input.images.contains(&candidate)
                        {
                            matches.insert(candidate);
                        }
                    }
                }
                if matches.is_empty() {
                    return Err("An executable mapping dependency is unavailable.");
                }
                pending.extend(matches);
            }
        }
        Ok(records)
    }
}

fn collect(input: &Input, deadline: Instant) -> Result<Value> {
    let parents = input
        .read_files
        .iter()
        .filter_map(|p| p.parent().map(Path::to_path_buf))
        .collect();
    let mut inspector = Inspector {
        input,
        deadline,
        parents,
        cache: BTreeMap::new(),
        total: 0,
    };
    let mut records = inspector
        .closure(input.images.iter().cloned().collect())
        .map_err(|_| "Linux executable mapping evidence could not be verified.")?;
    static LIBRARY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.so(?:\.[0-9]+)*$").unwrap());
    for module in input.read_files.difference(&input.images) {
        check(deadline)?;
        if !(module
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|v| LIBRARY.is_match(v))
            || module.extension() == Some(OsStr::new("node")))
        {
            continue;
        }
        if !(module.starts_with(&input.workspace)
            || input.runtime_roots.iter().any(|p| module.starts_with(p)))
        {
            continue;
        }
        match inspector.closure(vec![module.clone()]) {
            Ok(component) => records.extend(component),
            Err(_) => check(deadline)?,
        }
    }
    check(deadline)?;
    Ok(json!(records.into_values().collect::<Vec<_>>()))
}

/// Typed entry for in-process callers that already hold the read index, so a
/// full system index is not encoded as JSON only to be parsed straight back.
pub fn evidence(
    images: BTreeSet<PathBuf>,
    read_files: BTreeSet<PathBuf>,
    runtime_roots: Vec<PathBuf>,
    workspace: PathBuf,
    dependency_candidates: BTreeMap<String, BTreeSet<PathBuf>>,
    deadline: Instant,
) -> Result<Value> {
    check(deadline)?;
    let input = Input {
        images,
        read_files,
        runtime_roots,
        workspace,
        dependency_candidates: Some(dependency_candidates),
        ..Input::default()
    };
    collect(&input, deadline)
}

pub(super) fn evaluate(operation: &str, input: &Value, deadline: Instant) -> Option<Value> {
    if !matches!(operation, "mapping_evidence" | "mapping_elf") {
        return None;
    }
    let result = check(deadline)
        .and_then(|_| unpack(input, deadline))
        .and_then(|input| {
            serde_json::from_value::<Input>(input)
                .map_err(|_| "Invalid executable mapping request.")
        })
        .and_then(|input| {
            check(deadline)?;
            if operation == "mapping_evidence" {
                collect(&input, deadline)
            } else {
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&input.path)
                    .map_err(|_| "Invalid executable mapping file.")?;
                let metadata = file
                    .metadata()
                    .map_err(|_| "Invalid executable mapping file.")?;
                mapping_elf::inspect(
                    &mut file,
                    &metadata,
                    input.library,
                    input.system_library,
                    deadline,
                )
                .map(|v| json!(v))
            }
        })
        .and_then(|value| {
            if operation == "mapping_evidence" && input.get("mapping_snapshot").is_some() {
                super::mapping_snapshot::write(input, &value, deadline)
            } else {
                Ok(value)
            }
        });
    Some(match result {
        Ok(value) => json!({"value":value}),
        Err(message) => json!({"reason_code":"linux_mapping_unavailable","message":message}),
    })
}

fn unpack(input: &Value, deadline: Instant) -> Result<Value> {
    if input.get("mapping_snapshot").is_some() {
        return super::mapping_snapshot::read(input, deadline);
    }
    let Some(packed) = input.get("packed_json_gzip_v1") else {
        return Ok(input.clone());
    };
    if input.as_object().is_none_or(|v| v.len() != 2) {
        return Err("Invalid executable mapping request.");
    }
    let length = input["decoded_bytes"]
        .as_u64()
        .filter(|v| *v <= 256 * 1024 * 1024)
        .ok_or("Invalid executable mapping request.")?;
    let packed = packed
        .as_str()
        .filter(|v| v.len() <= 2 * 1024 * 1024)
        .ok_or("Invalid executable mapping request.")?;
    let compressed = STANDARD
        .decode(packed)
        .map_err(|_| "Invalid executable mapping request.")?;
    let bytes = crate::safe_decode::read_gzip(&compressed, length as usize + 1)?;
    if bytes.len() != length as usize {
        return Err("Invalid executable mapping request.");
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid executable mapping request.")
}
