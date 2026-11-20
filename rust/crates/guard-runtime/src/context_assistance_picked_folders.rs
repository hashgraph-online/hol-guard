//! The project folders a person picked by hand in the dashboard, kept so the
//! choice survives CIGAR restarting. Only folder and file paths are kept,
//! never file contents, and a restore repeats every check a new pick makes.
use super::*;

const SCHEMA: &str = "guard-cigar-picked-folders.v1";
const FILE: &str = "picked-folders.json";
const LIMIT: u64 = 64 * 1024;
pub(crate) const MAX_FOLDERS: usize = 8;
const MAX_FILES: usize = 32;

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Folder {
    pub(crate) workspace: PathBuf,
    pub(crate) sources: Vec<String>,
    pub(crate) notes_read: bool,
    pub(crate) notes_propose: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    folders: Vec<Folder>,
}

fn valid(folders: &[Folder]) -> bool {
    folders.len() <= MAX_FOLDERS
        && folders.iter().all(|folder| {
            folder.workspace.is_absolute()
                && folder.sources.len() <= MAX_FILES
                && folder.sources.iter().all(|source| !source.is_empty())
        })
}

/// `<home>/context-assistance`, created private when asked. `None` when it
/// does not exist yet and was not asked for.
fn directory(home: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    if !home.is_absolute()
        || home
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(error("home_invalid"));
    }
    if !create && fs::symlink_metadata(home.join("context-assistance")).is_err() {
        return Ok(None);
    }
    if create {
        crate::resident_state::ensure_private_directory_under(home, home, true)
            .map_err(|_| error("picked_folders_unavailable"))?;
    }
    validate_private_directory(home).map_err(|_| error("picked_folders_not_private"))?;
    let canonical = fs::canonicalize(home).map_err(|_| error("picked_folders_unavailable"))?;
    let directory = canonical.join("context-assistance");
    if create {
        crate::resident_state::ensure_private_directory_under(&directory, &canonical, true)
            .map_err(|_| error("picked_folders_unavailable"))?;
    }
    validate_private_directory(&directory).map_err(|_| error("picked_folders_not_private"))?;
    Ok(Some(directory))
}

pub(crate) fn load(home: &Path) -> Result<Vec<Folder>, String> {
    let Some(directory) = directory(home, false)? else {
        return Ok(Vec::new());
    };
    let Some((value, _)) =
        read_private_json(&directory.join(FILE), LIMIT, "cigar_picked_folders", home)
            .map_err(|_| error("picked_folders_invalid"))?
    else {
        return Ok(Vec::new());
    };
    let record: Record =
        crate::strict_json::from_value(value).map_err(|_| error("picked_folders_invalid"))?;
    if record.schema != SCHEMA || !valid(&record.folders) {
        return Err(error("picked_folders_invalid"));
    }
    Ok(record.folders)
}

pub(crate) fn save(home: &Path, folders: &[Folder]) -> Result<(), String> {
    if !valid(folders) {
        return Err(error("picked_folders_invalid"));
    }
    let directory = directory(home, true)?.ok_or_else(|| error("picked_folders_unavailable"))?;
    let record = Record {
        schema: SCHEMA.into(),
        folders: folders.to_vec(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| error("picked_folders_invalid"))?;
    persist_private_bytes(
        &directory.join(FILE),
        &bytes,
        LIMIT,
        "cigar_picked_folders",
        home,
    )
    .map_err(|_| error("picked_folders_write_failed"))
}

/// Deletes the record. Removing access must never leave an old record that a
/// later restore would grant again, so this is the fallback when a smaller
/// record cannot be written.
pub(crate) fn forget(home: &Path) -> Result<(), String> {
    let Some(directory) = directory(home, false)? else {
        return Ok(());
    };
    match fs::remove_file(directory.join(FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(error("picked_folders_write_failed"))
        }
        _ => Ok(()),
    }
}

#[cfg(all(test, unix))]
#[path = "context_assistance_picked_folders_tests.rs"]
mod tests;
