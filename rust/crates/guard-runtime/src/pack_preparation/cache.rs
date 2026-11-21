//! Immutable cache protocol and native executable admission.
use super::*;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
fn directory(path: &Path) -> Result<()> {
    if guard_secure_fs::contains_symlink_component(path) {
        return Err("pack preparation directory traverses a symlink".into());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|_| invalid())
}
pub(super) fn initialize(path: &Path) -> Result<()> {
    directory(&path.join("objects"))?;
    directory(&path.join("sets"))
}
fn publish(path: &Path, bytes: &[u8], reuse: bool) -> Result<()> {
    let parent = path.parent().ok_or_else(invalid)?;
    directory(parent)?;
    if path.try_exists().map_err(|_| invalid())? {
        let existing = guard_secure_fs::read_bounded(path, 65536).map_err(|_| invalid())?;
        if !reuse && existing.bytes != bytes {
            return Err("immutable pack object differs".into());
        }
        return Ok(());
    }
    let temporary = parent.join(format!(
        ".prepare-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temporary).map_err(|_| invalid())?;
    let result = (|| {
        file.write_all(bytes).map_err(|_| invalid())?;
        file.sync_all().map_err(|_| invalid())?;
        match fs::hard_link(&temporary, path) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = guard_secure_fs::read_bounded(path, 65536).map_err(|_| invalid())?;
                if !reuse && existing.bytes != bytes {
                    return Err("immutable pack object differs".into());
                }
            }
            Err(_) => return Err(invalid()),
        }
        #[cfg(unix)]
        {
            fs::File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(|_| invalid())?;
        }
        Ok(())
    })();
    let removed = fs::remove_file(&temporary).map_err(|_| invalid());
    result.and(removed)
}
fn put(directory: &Path, value: &Value) -> Result<Value> {
    let bytes = encoded(value)?;
    if bytes.is_empty() || bytes.len() > 65536 {
        return Err("pack cache metadata exceeds byte budget".into());
    }
    let sha = hash(&bytes);
    publish(
        &directory.join("objects").join(format!("{sha}.json")),
        &bytes,
        false,
    )?;
    Ok(json!({"sha256":sha,"length":bytes.len(),"expanded_length":bytes.len(),"kind":"data"}))
}
pub(super) fn finish(
    preparation: &Preparation<'_>,
    selected: &BTreeMap<String, (Value, Value)>,
    executables: &BTreeSet<String>,
) -> Result<Value> {
    let identities: Vec<Value> = selected.iter().map(|(id,(manifest,catalog))| json!({"extension":id,"program":manifest["program_digest"],"catalog":catalog,"trust":manifest["trust_digest"]})).collect();
    let digest = |domain: &[u8], value: &Value| -> Result<String> {
        let mut h = Sha256::new();
        h.update(domain);
        h.update(encoded(value)?);
        Ok(hex::encode(h.finalize()))
    };
    let engine = &preparation.input["engine"];
    let program = digest(
        b"hol-guard.active-command-program.v1\0",
        &json!({"engine":engine,"packs":identities}),
    )?;
    let catalog = digest(b"hol-guard.active-command-catalog.v1\0", &json!(identities))?;
    let trust = digest(b"hol-guard.active-command-trust.v1\0", &json!(identities))?;
    let release = put(preparation.directory, &preparation.root["policy"]["root"])?;
    let ordered: Vec<_> = selected.keys().collect();
    let mut next = Value::Null;
    for page in ordered.chunks(64).rev() {
        next = put(
            preparation.directory,
            &json!({"schema":"guard.command-pack-selection-page.v1","ids":page,"next":next}),
        )?;
    }
    let value = json!({"schema":"guard.command-pack-cache.v1","release":release,"selection":next,"selected_count":ordered.len()});
    publish(
        &preparation
            .directory
            .join("sets")
            .join(format!("{program}.json")),
        &encoded(&value)?,
        true,
    )?;
    let admitted = guard_command::native_command_program::NativeCommandProgram::from_pack_cache(
        preparation.directory,
        &program,
        guard_command::native_command_program::PackAdmissionBudget::resident(),
    )
    .map_err(Failure::from)?;
    if admitted.program_digest != program
        || admitted.catalog_digest != catalog
        || admitted.trust_digest != trust
    {
        return Err("native pack admission differs from prepared identities".into());
    }
    if admitted.extensions.len() != selected.len() {
        return Err("native pack admission differs from selected inventory".into());
    }
    Ok(
        json!({"program_digest":program,"catalog_digest":catalog,"trust_digest":trust,"selected":ordered,"registry_ids":preparation.details.keys().collect::<Vec<_>>(),"candidate_executables":executables,
        "catalog_refs":selected.values().map(|(m,_)| m["catalog"].clone()).collect::<Vec<_>>(),"registry_refs":preparation.details.values().map(|(r,_)| r["catalog_metadata"].clone()).collect::<Vec<_>>(),"selection_ref":next}),
    )
}
