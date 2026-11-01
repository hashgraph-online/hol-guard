//! Only this job's marked private roots are eligible for bounded cleanup.
use super::*;
use std::time::{Duration, Instant};

fn owned(home: &Path, path: &Path, job: &store::Job) -> Result<bool, String> {
    validate_private_directory(path).map_err(|_| error("install_cleanup_unsafe"))?;
    let marker: Option<Value> = store::private_read(
        home,
        &path.join("installation-owner.json"),
        4096,
        "cigar_install_job",
    )?;
    let Some(marker) = marker else {
        if fs::read_dir(path)
            .map_err(|_| error("install_cleanup_unsafe"))?
            .next()
            .is_none()
        {
            return Ok(true);
        }
        return Err(error("install_cleanup_ownership_missing"));
    };
    if marker["schema"] != "guard-cigar-install-owner.v1" {
        return Err(error("install_cleanup_unsafe"));
    }
    Ok(marker["job_id"] == job.request.job_id
        && marker["request_sha256"] == job.request_sha256
        && marker["slot"] == job.slot)
}
pub(super) fn collect(
    path: &Path,
    items: &mut Vec<(PathBuf, bool)>,
    bytes: &mut u64,
    depth: usize,
    deadline: Instant,
) -> Result<(), String> {
    if depth > 28 || items.len() > 16384 || Instant::now() >= deadline {
        return Err(error("install_cleanup_limit"));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| error("install_cleanup_unsafe"))?;
    if metadata.file_type().is_symlink() {
        return Err(error("install_cleanup_unsafe"));
    }
    if metadata.is_dir() {
        validate_private_directory(path).map_err(|_| error("install_cleanup_unsafe"))?;
        for entry in fs::read_dir(path).map_err(|_| error("install_cleanup_unsafe"))? {
            collect(
                &entry.map_err(|_| error("install_cleanup_unsafe"))?.path(),
                items,
                bytes,
                depth + 1,
                deadline,
            )?;
        }
        items.push((path.into(), true));
    } else if metadata.is_file() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 || metadata.uid() != nix::unistd::geteuid().as_raw() {
                return Err(error("install_cleanup_unsafe"));
            }
        }
        *bytes = bytes
            .checked_add(metadata.len())
            .ok_or_else(|| error("install_cleanup_limit"))?;
        if *bytes > 512 * 1024 * 1024 {
            return Err(error("install_cleanup_limit"));
        }
        items.push((path.into(), false));
    } else {
        return Err(error("install_cleanup_unsafe"));
    }
    Ok(())
}
pub(super) fn remove_collected(
    root: &Path,
    items: Vec<(PathBuf, bool)>,
    deadline: Instant,
) -> Result<(), String> {
    let marker = root.join("installation-owner.json");
    for (path, directory) in items {
        if path == root || path == marker {
            continue;
        }
        if Instant::now() >= deadline {
            return Err(error("install_cleanup_limit"));
        }
        if directory {
            fs::remove_dir(path)
        } else {
            fs::remove_file(path)
        }
        .map_err(|_| error("install_cleanup_failed"))?;
    }
    if Instant::now() >= deadline {
        return Err(error("install_cleanup_limit"));
    }
    if marker.exists() {
        fs::remove_file(marker).map_err(|_| error("install_cleanup_failed"))?;
    }
    fs::remove_dir(root).map_err(|_| error("install_cleanup_failed"))
}

fn roots(home: &Path, job: &store::Job, paths: &[(&str, &str)]) -> Result<(), String> {
    // A config reference protects a slot even if its publication record needs
    // repair. Never infer that external data or a selected slot is disposable.
    let settings = crate::guard_config_load::context_assistance_config(home)
        .map_err(|_| error("configuration_unavailable"))?;
    if settings.requested.runtime_id == job.runtime_id
        && paths
            .iter()
            .any(|(parent, _)| matches!(*parent, "bundles" | "work"))
    {
        return Err(error("install_slot_selected"));
    }
    let mut references = Vec::new();
    for option in super::super::list(home)? {
        let id = option["runtime_id"]
            .as_str()
            .ok_or_else(|| error("installation_invalid"))?;
        let record = load(home, id)?;
        references.extend([
            record.selection.python,
            record.selection.site_packages,
            record.selection.work_dir,
        ]);
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    for &(parent, slot) in paths {
        let parent = home.join("context-assistance").join(parent);
        match fs::symlink_metadata(&parent) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(error("install_cleanup_unsafe")),
            Ok(_) => {}
        }
        validate_private_directory(&parent).map_err(|_| error("install_cleanup_unsafe"))?;
        let path = parent.join(slot);
        if references
            .iter()
            .any(|reference| reference.starts_with(&path))
        {
            return Err(error("install_slot_in_use"));
        }
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(error("install_cleanup_unsafe")),
            Ok(_) => {}
        }
        if !owned(home, &path, job)? {
            continue;
        }
        let mut items = Vec::new();
        collect(&path, &mut items, &mut 0, 0, deadline)?;
        remove_collected(&path, items, deadline)?;
    }
    Ok(())
}

pub(super) fn downloads(home: &Path, job: &store::Job) -> Result<(), String> {
    let id = record_name(&job.request.job_id);
    roots(home, job, &[("downloads", id.trim_end_matches(".json"))])
}
pub(super) fn verification(home: &Path, job: &store::Job) -> Result<(), String> {
    let id = record_name(&job.request.job_id);
    roots(home, job, &[("verification", id.trim_end_matches(".json"))])
}
pub(super) fn cleanup(home: &Path, job: &store::Job) -> Result<(), String> {
    let id = record_name(&job.request.job_id);
    roots(
        home,
        job,
        &[
            ("downloads", id.trim_end_matches(".json")),
            ("staging", id.trim_end_matches(".json")),
            ("bundles", job.slot.as_str()),
            ("work", job.slot.as_str()),
        ],
    )
}
