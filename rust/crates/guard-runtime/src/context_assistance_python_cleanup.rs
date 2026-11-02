//! Cleanup only exact job-owned preparation roots; registered runtimes and
//! external interpreter aliases protect their referenced files from deletion.
use super::*;
use std::time::Instant;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    schema: String,
    job_id: String,
    request_sha256: String,
    slot: String,
}
fn references(home: &Path) -> Result<Vec<PathBuf>, String> {
    let mut result = Vec::new();
    for value in interpreters::interpreters(home)? {
        let id = value["interpreter_id"]
            .as_str()
            .ok_or_else(|| error("interpreter_invalid"))?;
        let record = interpreters::load_interpreter(home, id)?;
        if let Ok(canonical) = fs::canonicalize(&record.python) {
            result.push(canonical);
        }
        result.push(record.python);
        if let Some(managed) = record.managed_python {
            result.push(managed.selection.root);
        }
    }
    for value in super::super::list(home)? {
        let id = value["runtime_id"]
            .as_str()
            .ok_or_else(|| error("installation_invalid"))?;
        let record = load(home, id)?;
        result.extend([
            record.selection.python,
            record.selection.site_packages,
            record.selection.work_dir,
        ]);
    }
    Ok(result)
}
fn roots(home: &Path, job: &python_store::Job, paths: &[(&str, &str)]) -> Result<(), String> {
    let references = references(home)?;
    let deadline = Instant::now() + cleanup::CLEANUP_TIME;
    for (parent, name) in paths {
        let parent_path = home.join("context-assistance").join(parent);
        match fs::symlink_metadata(&parent_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(error("install_cleanup_unsafe")),
            Ok(_) => {}
        }
        let path = store::directory(home, parent, false)?.join(name);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(error("install_cleanup_unsafe")),
            Ok(_) => {}
        }
        if references
            .iter()
            .any(|reference| reference.starts_with(&path) || path.starts_with(reference))
        {
            return Err(error("install_slot_in_use"));
        }
        validate_private_directory(&path).map_err(|_| error("install_cleanup_unsafe"))?;
        let owner: Owner = store::private_read(
            home,
            &path.join("installation-owner.json"),
            4096,
            "cigar_python_job",
        )?
        .ok_or_else(|| error("install_cleanup_ownership_missing"))?;
        if owner.schema != "guard-cigar-python-install-owner.v1" {
            return Err(error("install_cleanup_unsafe"));
        }
        if owner.job_id != job.request.job_id
            || owner.request_sha256 != job.request_sha256
            || owner.slot != job.slot
        {
            continue;
        }
        let mut items = Vec::new();
        cleanup::collect(&path, &mut items, &mut 0, 0, deadline)?;
        cleanup::remove_collected(&path, items, deadline)?;
    }
    Ok(())
}
pub(super) fn downloads(home: &Path, job: &python_store::Job) -> Result<(), String> {
    let id = record_name(&job.request.job_id);
    roots(
        home,
        job,
        &[("python-downloads", id.trim_end_matches(".json"))],
    )
}
pub(super) fn cleanup(home: &Path, job: &python_store::Job) -> Result<(), String> {
    let id = record_name(&job.request.job_id);
    let id = id.trim_end_matches(".json");
    roots(
        home,
        job,
        &[
            ("python-staging", id),
            ("python", &job.slot),
            ("python-work", &job.slot),
            ("python-downloads", id),
        ],
    )
}
