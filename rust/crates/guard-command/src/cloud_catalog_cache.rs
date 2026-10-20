//! Bounded durable private page cache. All reads revalidate canonical bytes.
use super::*;
use std::fs::{self, OpenOptions};
use std::io::Write;

pub(super) fn lock_file(path: &Path) -> Result<fs::File> {
    if guard_secure_fs::contains_symlink_component(path) {
        return Err(Error::Invalid);
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

pub fn draft(directory: &Path) -> Result<(TempDir, fs::File)> {
    let lock = lock_file(&directory.join("cache.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let mut active = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("draft-"))
        {
            continue;
        }
        if !entry.file_type()?.is_dir() {
            return Err(Error::Invalid);
        }
        let lease = lock_file(&entry.path().join("lease"))?;
        if fs2::FileExt::try_lock_exclusive(&lease).is_ok() {
            // Windows cannot remove a directory while a file in it is open.
            // The cache lock keeps any other draft or acquire out meanwhile.
            drop(lease);
            fs::remove_dir_all(entry.path())?;
        } else {
            active += 1;
        }
    }
    if active >= 4 {
        return Err(Error::Limit);
    }
    let spool = tempfile::Builder::new()
        .prefix("draft-")
        .tempdir_in(directory)?;
    let lease = lock_file(&spool.path().join("lease"))?;
    fs2::FileExt::lock_exclusive(&lease)?;
    Ok((spool, lease))
}

fn leases() -> &'static Mutex<Vec<(String, PathBuf, fs::File)>> {
    static LEASES: OnceLock<Mutex<Vec<(String, PathBuf, fs::File)>>> = OnceLock::new();
    LEASES.get_or_init(Default::default)
}

pub fn directory(home: &Path) -> Result<PathBuf> {
    if !home.is_absolute() {
        return Err(Error::Invalid);
    }
    for parent in home.ancestors() {
        if parent
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(Error::Invalid);
        }
    }
    let directory = home.join("native-runtime/cloud-catalog");
    for path in [home.join("native-runtime"), directory.clone()] {
        match fs::symlink_metadata(&path) {
            Ok(m) => {
                if !m.is_dir() || m.file_type().is_symlink() {
                    return Err(Error::Invalid);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if m.mode() & 0o077 != 0 || m.uid() != nix::unistd::Uid::effective().as_raw() {
                        return Err(Error::Invalid);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                #[cfg_attr(not(unix), allow(unused_mut))]
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(&path)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(directory)
}
pub fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
    if guard_secure_fs::contains_symlink_component(path) {
        return Err(Error::Invalid);
    }
    guard_secure_fs::read_bounded(path, max)
        .map(|v| v.bytes)
        .map_err(|_| Error::Unavailable)
}
pub(super) fn record(directory: &Path) -> Result<Value> {
    let bytes = read(&directory.join("record.json"), 2 * 1024 * 1024)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    if encode(&value)? != bytes {
        return Err(Error::Invalid);
    }
    let hashes = value["hashes"].as_array().ok_or(Error::Invalid)?;
    if hashes.is_empty()
        || hashes.len() > MAX_PAGES
        || value["manifest"]["pageCount"] != hashes.len()
    {
        return Err(Error::Invalid);
    }
    Ok(value)
}
fn views(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name().to_str().is_some_and(sha) {
            if !entry.file_type()?.is_dir() {
                return Err(Error::Invalid);
            }
            paths.push(entry.path());
        }
    }
    paths.sort_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok());
    Ok(paths)
}
pub fn publish(spool: TempDir, draft_lease: fs::File, new: Value) -> Result<Value> {
    let observation: Observation =
        serde_json::from_value(new["observation"].clone()).map_err(|_| Error::Invalid)?;
    let directory = directory(&observation.guard_home)?;
    // Serialize durable publication/eviction across both CLI and resident.
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(directory.join("cache.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let paths = views(&directory)?;
    for path in &paths {
        let Ok(old) = record(path) else {
            continue;
        };
        let mut a = old["observation"].clone();
        let mut b = new["observation"].clone();
        a.as_object_mut()
            .ok_or(Error::Invalid)?
            .remove("generated_at");
        b.as_object_mut()
            .ok_or(Error::Invalid)?
            .remove("generated_at");
        if a == b && old["manifest"]["catalogDigest"] == new["manifest"]["catalogDigest"] {
            verify(path, &old)?;
            return summary(&old);
        }
    }
    // An in-flight transfer keeps its immutable pages even when other views
    // are published. Refuse preparation if all four cache slots are pinned.
    let mut evict = Vec::new();
    for path in &paths {
        if paths.len().saturating_sub(evict.len()) < 4 {
            break;
        }
        let lease = lock_file(&path.join("lease"))?;
        if fs2::FileExt::try_lock_exclusive(&lease).is_ok() {
            evict.push((path, lease));
        }
    }
    if paths.len().saturating_sub(evict.len()) >= 4 {
        return Err(Error::Limit);
    }
    let token = digest(&new["manifest"])?;
    write(&spool.path().join("record.json"), &encode(&new)?)?;
    let target = directory.join(&token);
    if target.exists() {
        return Err(Error::Invalid);
    }
    // Windows refuses to rename a directory while a file inside it is open.
    // The cache lock held here already keeps every reaper and acquire away
    // from the draft, so its lease can close before the rename.
    drop(draft_lease);
    fs::rename(spool.path(), &target)?;
    #[cfg(unix)]
    fs::File::open(&directory)?.sync_all()?;
    for (path, lease) in evict {
        drop(lease);
        fs::remove_dir_all(path)?;
    }
    summary(&new)
}
fn summary(value: &Value) -> Result<Value> {
    Ok(
        json!({"manifest":value["manifest"],"token":digest(&value["manifest"])?,
        "discovery_root":value["observation"]["discovery_root"],
        "discovery_authority":value["observation"]["discovery_authority"]}),
    )
}
pub(super) fn page(directory: &Path, value: &Value, ordinal: usize) -> Result<Vec<u8>> {
    let hashes = value["hashes"].as_array().ok_or(Error::Invalid)?;
    let expected = hashes
        .get(ordinal)
        .and_then(Value::as_str)
        .ok_or(Error::Invalid)?;
    let bytes = read(&directory.join(format!("{ordinal}.json")), MAX_PAGE)?;
    if hash(&bytes) != expected {
        return Err(Error::Invalid);
    }
    let mut page: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
    if encode(&page)? != bytes || page["ordinal"] != ordinal {
        return Err(Error::Invalid);
    }
    let claimed = page
        .as_object_mut()
        .ok_or(Error::Invalid)?
        .remove("pageDigest")
        .ok_or(Error::Invalid)?;
    if json!(digest(&page)?) != claimed {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
pub(super) fn verify(directory: &Path, value: &Value) -> Result<()> {
    let count = value["hashes"].as_array().ok_or(Error::Invalid)?.len();
    let mut previous = Value::Null;
    let mut seen = 0;
    let mut total = 0;
    let mut last_id = String::new();
    for ordinal in 0..count {
        let bytes = page(directory, value, ordinal)?;
        total += bytes.len();
        let p: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
        if p["previousDigest"] != previous {
            return Err(Error::Invalid);
        }
        let entries = p["entries"].as_array().ok_or(Error::Invalid)?;
        if entries.is_empty() || entries.len() > 64 {
            return Err(Error::Invalid);
        }
        for e in entries {
            let id = e["id"].as_str().ok_or(Error::Invalid)?;
            if id <= last_id.as_str() {
                return Err(Error::Invalid);
            }
            last_id = id.to_owned();
            seen += 1;
        }
        previous = p["pageDigest"].clone();
    }
    let manifest = &value["manifest"];
    if manifest["extensionCount"] != seen
        || manifest["lastPageDigest"] != previous
        || total > MAX_TOTAL
        || value["totalBytes"] != total
        || manifest["catalogDigest"]
            != digest(&json!({
            "schemaVersion":"guard.extension-catalog-view.v2","pageCount":count,"extensionCount":seen,"lastPageDigest":previous}))?
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn legacy(path: &Path, record: &Value) -> Result<Value> {
    let manifest = &record["manifest"];
    if manifest["extensionCount"].as_u64().ok_or(Error::Invalid)? > 512 {
        return Err(Error::Limit);
    }
    verify(path, record)?;
    let mut entries = Vec::new();
    let mut size = 0;
    for ordinal in 0..record["hashes"].as_array().ok_or(Error::Invalid)?.len() {
        let p: Value =
            serde_json::from_slice(&page(path, record, ordinal)?).map_err(|_| Error::Invalid)?;
        for entry in p["entries"].as_array().ok_or(Error::Invalid)? {
            size += encode(entry)?.len();
            if size > 1_000_000 {
                return Err(Error::Limit);
            }
            entries.push(entry.clone());
        }
    }
    let extensions = json!(entries);
    let wire = json!({"schemaVersion":"guard.extension-catalog.v1","catalogDigest":digest(&extensions)?,
        "guardVersion":manifest["guardVersion"],"generatedAt":manifest["generatedAt"],
        "controlSchemaVersion":manifest["controlSchemaVersion"],"extensions":extensions,
        "limits":{"maxExtensions":512,"maxPermissionsPerExtension":512,"maxPayloadBytes":1_000_000,"maxStringLength":8192}});
    if encode(&wire)?.len() > 1_000_000 {
        return Err(Error::Limit);
    }
    Ok(wire)
}
pub fn evaluate(request: &Value) -> Result<Value> {
    let home = Path::new(request["guard_home"].as_str().ok_or(Error::Invalid)?);
    let root = directory(home)?;
    if request["action"] == "release" {
        let id = request["lease"].as_str().ok_or(Error::Invalid)?;
        let mut held = leases().lock().map_err(|_| Error::Unavailable)?;
        let index = held
            .iter()
            .position(|(token, path, _)| token == id && path.starts_with(&root))
            .ok_or(Error::Unavailable)?;
        held.remove(index);
        return Ok(json!({}));
    }
    if request["action"] == "observe" {
        // Publication evicts views under the exclusive cache lock, so a shared
        // lock keeps every view this read verifies in place until it returns.
        let lock = lock_file(&root.join("cache.lock"))?;
        fs2::FileExt::lock_shared(&lock)?;
        for path in views(&root)? {
            let value = record(&path)?;
            if value["manifest"]["catalogDigest"] == request["view_digest"]
                && value["manifest"]["enforcementCatalogDigest"] == request["enforcement_digest"]
                && value["manifest"]["generatedAt"] == request["generated_at"]
            {
                verify(&path, &value)?;
                return summary(&value);
            }
        }
        return Err(Error::Unavailable);
    }
    let token = request["token"]
        .as_str()
        .filter(|s| sha(s))
        .ok_or(Error::Invalid)?;
    let path = root.join(token);
    if request["action"] == "acquire" {
        let lock = lock_file(&root.join("cache.lock"))?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let mut held = leases().lock().map_err(|_| Error::Unavailable)?;
        if held.len() >= 4 {
            return Err(Error::Limit);
        }
        // A missing/evicted view is never recreated by an acquire request.
        let value = record(&path)?;
        verify(&path, &value)?;
        let lease = lock_file(&path.join("lease"))?;
        fs2::FileExt::lock_shared(&lease)?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
        let id = hex::encode(nonce);
        held.push((id.clone(), path, lease));
        return Ok(json!({"lease":id}));
    }
    let record = record(&path)?;
    if digest(&record["manifest"])? != token {
        return Err(Error::Invalid);
    }
    if request["action"] == "sync_plan" {
        return super::sync::plan(&record["manifest"], request);
    }
    if request["action"] == "sync_ack" {
        return super::sync::ack(&record["manifest"], request);
    }
    if request["action"] == "legacy" {
        return Ok(json!({"catalog":legacy(&path,&record)?}));
    }
    let op = request["operation"].as_str().ok_or(Error::Invalid)?;
    let key = format!("catalog-v2:{token}");
    let manifest = &record["manifest"];
    let body = match op {
        "begin" => {
            verify(&path, &record)?;
            json!({"operation":op,"idempotencyKey":key,"manifest":manifest})
        }
        "page" => {
            let ordinal = request["ordinal"].as_u64().ok_or(Error::Invalid)? as usize;
            let page: Value = serde_json::from_slice(&page(&path, &record, ordinal)?)
                .map_err(|_| Error::Invalid)?;
            json!({"operation":op,"idempotencyKey":key,"catalogDigest":manifest["catalogDigest"],"page":page})
        }
        "complete" => {
            verify(&path, &record)?;
            json!({"operation":op,"idempotencyKey":key,"catalogDigest":manifest["catalogDigest"]})
        }
        _ => return Err(Error::Invalid),
    };
    let bytes = encode(&body)?;
    if bytes.len() > MAX_PAGE + 1024 {
        return Err(Error::Limit);
    }
    // Resident frames remain at their existing 2 MiB cap even when a wire page
    // fills 2 MiB. Python joins bounded raw chunks, never rebuilds a page.
    use base64::{engine::general_purpose::STANDARD, Engine};
    let offset = request["offset"].as_u64().unwrap_or(0) as usize;
    if offset >= bytes.len() {
        return Err(Error::Invalid);
    }
    let end = (offset + 512 * 1024).min(bytes.len());
    Ok(
        json!({"body_chunk":STANDARD.encode(&bytes[offset..end]),"total_bytes":bytes.len(),
        "body_sha256":hash(&bytes),"offset":offset}),
    )
}
