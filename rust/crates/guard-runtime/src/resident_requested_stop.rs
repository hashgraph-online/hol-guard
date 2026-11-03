//! The note a serving child leaves when a `shutdown` operation, rather than a
//! fault, ended its run.
//!
//! The note crosses exactly one process boundary, from the serving child to
//! the supervisor that reaps it, and the one thing both processes already
//! know about that single run is the child's process id. Naming the note
//! after it means a supervisor reads its own child's note and nothing else,
//! so two supervisors whose runs overlap in a scope -- a Unix supervisor can
//! still be draining its child's stderr while the next one starts and
//! finishes -- cannot take or discard each other's. Nothing here reads a
//! clock either, so an adjustment between the spawn and the stop cannot turn
//! an orderly stop back into a crash.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

#[cfg(windows)]
use super::private_file::recover_interrupted_replace;
use super::private_file::{read_private_bytes, remove_private, write_private};

const REQUESTED_STOP_SCHEMA: &str = "hol-guard-resident-requested-stop.v1";
const REQUESTED_STOP_PREFIX: &str = "requested-stop.";
const REQUESTED_STOP_SUFFIX: &str = ".json";

/// How many notes a scope may hold before a reaping supervisor clears out the
/// ones that are not its own.
///
/// A note is only ever honoured for the exact child a supervisor reaped, so
/// one left behind cannot forgive another run; the sweep is only here to stop
/// a scope collecting files when a supervisor is killed before it reaps. A
/// process id is reused eventually, and a note left by an earlier child that
/// held the same id can be honoured for a later one -- that forgives a single
/// crash charge, which is why the number of notes that can wait around for
/// that coincidence is bounded.
const MAX_STOP_NOTES: usize = 8;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedStop {
    schema: String,
    process_id: u32,
}

fn note_path(scope: &Path, process_id: u32) -> PathBuf {
    scope.join(format!(
        "{REQUESTED_STOP_PREFIX}{process_id}{REQUESTED_STOP_SUFFIX}"
    ))
}

fn is_note(name: &str) -> bool {
    name.starts_with(REQUESTED_STOP_PREFIX) && name.ends_with(REQUESTED_STOP_SUFFIX)
}

/// Say that this run is ending because something asked it to stop.
///
/// The serving child is the only process that knows a `shutdown` operation
/// ended its serve loop: its supervisor sees a process that exited cleanly
/// after a few milliseconds, which on its own is indistinguishable from a
/// crash loop reporting success.
pub(super) fn record(scope: &Path, process_id: u32) -> Result<(), String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let note = RequestedStop {
        schema: REQUESTED_STOP_SCHEMA.to_owned(),
        process_id,
    };
    let encoded = serde_json::to_vec(&note)
        .map_err(|_| "native_resident_requested_stop_encode_failed".to_owned())?;
    write_private(&note_path(scope, process_id), &encoded, &private_root)
}

/// Take the note left by the child this supervisor has just reaped.
///
/// The note is removed as it is read, so a run is forgiven once. A note that
/// cannot be read, or that names another process, is no note at all and the
/// run keeps the charge its spawn took.
pub(super) fn take(scope: &Path, child_process_id: u32) -> bool {
    let Ok(private_root) = crate::resident_state::private_root_for_scope(scope) else {
        return false;
    };
    let path = note_path(scope, child_process_id);
    #[cfg(windows)]
    {
        if recover_interrupted_replace(&path, &private_root).is_err() {
            return false;
        }
    }
    let recorded = read_note(&path, &private_root);
    remove_private(&path, &private_root);
    sweep(scope, &private_root);
    recorded == Some(child_process_id)
}

fn read_note(path: &Path, private_root: &Path) -> Option<u32> {
    let bytes = read_private_bytes(path, private_root, "requested_stop").ok()??;
    let value = crate::strict_json_value(&bytes).ok()?;
    let note = serde_json::from_value::<RequestedStop>(value).ok()?;
    (note.schema == REQUESTED_STOP_SCHEMA).then_some(note.process_id)
}

/// Clear the oldest notes once a scope has collected more than any plausible
/// overlap of runs, so notes whose supervisor never came back for them cannot
/// pile up. The newest are kept, because those are the ones a live supervisor
/// is still on its way to read. Best effort throughout: a note that stays
/// costs one small file and can only ever be read by a run that names the
/// same process.
fn sweep(scope: &Path, private_root: &Path) {
    let Ok(entries) = std::fs::read_dir(scope) else {
        return;
    };
    let mut notes: Vec<(SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_str().is_some_and(is_note))
        .filter_map(|entry| {
            let written = entry.metadata().and_then(|data| data.modified()).ok()?;
            Some((written, entry.path()))
        })
        .collect();
    if notes.len() <= MAX_STOP_NOTES {
        return;
    }
    notes.sort_by(|left, right| right.0.cmp(&left.0));
    for (_, note) in notes.into_iter().skip(MAX_STOP_NOTES) {
        remove_private(&note, private_root);
    }
}

#[cfg(test)]
#[path = "resident_requested_stop_tests.rs"]
mod tests;
