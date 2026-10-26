//! Called under the control mutation lease; the cache lease fences preparers.
use super::*;
use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::Read;

pub(super) fn run(input: &Value) -> Result<Value> {
    let directory = Path::new(input["directory"].as_str().ok_or_else(invalid)?);
    let path = directory.join(".cache-lease");
    if guard_secure_fs::contains_symlink_component(&path) {
        return Err(invalid());
    }
    let leaf = std::fs::symlink_metadata(&path).map_err(|_| invalid())?;
    if !leaf.is_file() {
        return Err(invalid());
    }
    // One handle checks identity, takes the lease and reads the byte. Preparers
    // hold the lease open for writing, so a second read-only open would fail on
    // Windows with a sharing violation instead of reporting the cache busy.
    // No replacement/unlink of this inode is permitted by any cache writer.
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(&path).map_err(|_| invalid())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(|_| invalid())?;
        if !opened.is_file()
            || opened.nlink() != 1
            || opened.dev() != leaf.dev()
            || opened.ino() != leaf.ino()
        {
            return Err(invalid());
        }
    }
    #[cfg(windows)]
    {
        let (expected, links) =
            guard_runtime_windows_process::regular_file_id(&path, false).map_err(|_| invalid())?;
        let opened = guard_runtime_windows_process::handle_file_id(&file).map_err(|_| invalid())?;
        if links != 1 || opened != expected {
            return Err(invalid());
        }
    }
    if guard_secure_fs::contains_symlink_component(&path) {
        return Err(invalid());
    }
    if file.try_lock_exclusive().is_err() {
        return Ok(json!({"busy":true,"evicted":0}));
    }
    let mut locked = Vec::with_capacity(2);
    (&file)
        .take(2)
        .read_to_end(&mut locked)
        .map_err(|_| invalid())?;
    if locked != b"0" {
        return Err(invalid());
    }
    let key = hex::decode(input["key"].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    if key.len() != 32 {
        return Err(invalid());
    }
    let rows = input["activations"]
        .as_array()
        .filter(|a| a.len() <= 1024)
        .ok_or_else(invalid)?;
    let mut objects = BTreeSet::new();
    let mut sets = BTreeSet::new();
    for row in rows {
        let header = crate::active_pack_security::active(row, &key)?;
        let program = header["program_digest"]
            .as_str()
            .filter(|s| hex(s, 64))
            .ok_or_else(invalid)?;
        sets.insert(program.to_owned());
        let set = decode(&read(
            &directory.join("sets").join(format!("{program}.json")),
            65536,
        )?)?;
        let mut graph = graph::Graph::new(directory);
        let release = graph.blob(&set["release"], 0)?.ok_or_else(invalid)?;
        // Metadata linked by the authenticated header is pinned transitively.
        // Distribution is a terminal public Root, not a selection of every pack.
        graph
            .blob(&header["distribution"], 0)?
            .ok_or_else(invalid)?;
        for (field, schema, count_field) in [
            (
                "registry",
                "guard.command-pack-registry-page.v1",
                "registry_count",
            ),
            (
                "executables",
                "guard.command-pack-executables-page.v1",
                "executable_count",
            ),
        ] {
            let maximum = if field == "executables" {
                1048576
            } else {
                32768
            };
            let expected = header[count_field]
                .as_u64()
                .filter(|n| *n <= maximum)
                .ok_or_else(invalid)? as usize;
            let mut next = header[field].clone();
            let mut pages = BTreeSet::new();
            let mut count = 0usize;
            while !next.is_null() {
                let sha = next["sha256"].as_str().ok_or_else(invalid)?;
                if !pages.insert(sha.to_owned()) || pages.len() > expected {
                    return Err(invalid());
                }
                let page = decode(&graph.blob(&next, 0)?.ok_or_else(invalid)?)?;
                let items = page["items"]
                    .as_array()
                    .filter(|a| !a.is_empty() && a.len() <= 64)
                    .ok_or_else(invalid)?;
                if page["schema"] != schema {
                    return Err(invalid());
                }
                count += items.len();
                if count > expected {
                    return Err(invalid());
                }
                for item in items {
                    graph.walk(item, 0)?;
                }
                next = page["next"].clone();
            }
            if count != expected {
                return Err(invalid());
            }
        }
        if graph.unavailable || !graph.needs.is_empty() {
            return Err(invalid());
        }
        let mut selected = BTreeSet::new();
        let expected = header["selected_count"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 32768)
            .ok_or_else(invalid)? as usize;
        let mut page = header["selection"].clone();
        let mut seen = BTreeSet::new();
        while !page.is_null() {
            let sha = page["sha256"].as_str().ok_or_else(invalid)?;
            if !seen.insert(sha.to_owned()) || seen.len() > 32768 {
                return Err(invalid());
            }
            let value = decode(&graph.blob(&page, 0)?.ok_or_else(invalid)?)?;
            if value["schema"] != "guard.command-pack-selection-page.v1" {
                return Err(invalid());
            }
            for id in value["ids"]
                .as_array()
                .filter(|a| !a.is_empty() && a.len() <= 64)
                .ok_or_else(invalid)?
            {
                let id = id.as_str().ok_or_else(invalid)?;
                if selected.len() >= expected
                    || selected.last().is_some_and(|s: &String| s.as_str() >= id)
                {
                    return Err(invalid());
                }
                selected.insert(id.to_owned());
            }
            page = value["next"].clone();
        }
        if header["selected_count"].as_u64() != Some(selected.len() as u64)
            || set["selection"] != header["selection"]
        {
            return Err(invalid());
        }
        let admitted=guard_command::native_command_program::NativeCommandProgram::from_integrity_bound_packs(
            &release,&hash(&release),&selected,guard_command::native_command_program::PackAdmissionBudget::resident(),
            |id| {
                let bytes=guard_secure_fs::read_bounded(&directory.join("objects").join(format!("{id}.json")),65536)
                    .map(|r|r.bytes).map_err(|_| "offline_cache_pin_unavailable")?;
                objects.insert(id.to_owned()); Ok(bytes)
            }).map_err(str::to_owned)?;
        if admitted.program_digest != program {
            return Err(invalid());
        }
        objects.extend(graph.objects);
    }
    // These are captured by the fixed existing protected marker/floor readers,
    // under the control lease. A rolled-back/lost SQLite row must not cause
    // collection of the program independently retained by the native marker.
    let marker = &input["control_authority"];
    let floor = &input["control_floor"];
    if !marker.is_null() {
        if marker["phase"] != "committed" {
            return Err("offline_cache_authority_not_current".into());
        }
        if let Some(program) = marker["pack_program_digest"].as_str() {
            if !sets.contains(program) {
                return Err("offline_cache_active_record_missing".into());
            }
        } else if !rows.is_empty() {
            return Err("offline_cache_active_marker_missing".into());
        }
    } else if !rows.is_empty() || !floor.is_null() {
        return Err("offline_cache_active_marker_missing".into());
    }
    if !floor.is_null() {
        if marker["effective_digest"] != floor["effective_digest"] {
            return Err("offline_cache_authority_not_current".into());
        }
        if !floor["authority"].is_null() {
            for field in ["epoch", "mutation_revision", "authority_key_id", "recovery"] {
                if marker[field] != floor["authority"][field] {
                    return Err("offline_cache_authority_not_current".into());
                }
            }
        }
    }
    let maximum = input["maximum_bytes"]
        .as_u64()
        .filter(|n| *n <= LIMIT as u64)
        .ok_or_else(invalid)?;
    let mut candidates = Vec::new();
    let mut total = 0u64;
    let mut scanned = 0usize;
    for (family, suffix, pins) in [
        ("objects", "json", &objects),
        ("sets", "json", &sets),
        ("archives", "zip", &BTreeSet::new()),
        ("transfers", "zip", &BTreeSet::new()),
    ] {
        let parent = directory.join(family);
        if !parent.exists() {
            continue;
        }
        if std::fs::symlink_metadata(&parent)
            .map_err(|_| invalid())?
            .file_type()
            .is_symlink()
        {
            return Err(invalid());
        }
        for entry in std::fs::read_dir(&parent).map_err(|_| invalid())? {
            scanned += 1;
            if scanned > 1048576 {
                return Err("offline_cache_scan_budget_exceeded".into());
            }
            let entry = entry.map_err(|_| invalid())?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(invalid)?;
            let id = name
                .strip_suffix(&format!(".{suffix}"))
                .filter(|s| hex(s, 64));
            let temporary = [".obj-", ".set-", ".transfer-"].iter().any(|prefix| {
                name.strip_prefix(prefix).is_some_and(|tail| {
                    tail.len() == 8
                        && tail
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                })
            }) || name.strip_prefix(".prepare-").is_some_and(|tail| {
                // pack_preparation::cache writes `.prepare-<pid>-<serial>`.
                tail.split_once('-').is_some_and(|(pid, serial)| {
                    [pid, serial].iter().all(|part| {
                        (1..=20).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit())
                    })
                })
            });
            if id.is_none() && !temporary {
                continue;
            }
            let metadata = entry.path().symlink_metadata().map_err(|_| invalid())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(invalid());
            }
            total = total.checked_add(metadata.len()).ok_or_else(invalid)?;
            if id.is_none_or(|id| !pins.contains(id)) {
                candidates.push((
                    metadata.modified().map_err(|_| invalid())?,
                    entry.path(),
                    metadata.len(),
                ));
            }
        }
    }
    // Plan completely before the first unlink. A crash can leave only surplus
    // unreferenced objects; immutable active/pending objects and floors survive.
    candidates.sort();
    let mut evicted = 0;
    let mut bytes = 0;
    for (_, path, size) in candidates {
        if total <= maximum {
            break;
        }
        std::fs::remove_file(path).map_err(|_| invalid())?;
        total -= size;
        bytes += size;
        evicted += 1;
    }
    #[cfg(unix)]
    for family in ["objects", "sets", "archives", "transfers"] {
        let path = directory.join(family);
        if path.exists() {
            std::fs::File::open(path)
                .and_then(|f| f.sync_all())
                .map_err(|_| invalid())?;
        }
    }
    Ok(
        json!({"evicted":evicted,"evicted_bytes":bytes,"remaining_bytes":total,
        "pinned_objects":objects.len(),"pinned_sets":sets.len(),"over_budget":total>maximum}),
    )
}
