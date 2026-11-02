//! Folders picked by hand in the dashboard outlive the worker that holds
//! them. A new worker picks each one again through the same checks as the
//! first pick; agent apps are never restored and must be approved again.
use super::*;
use crate::policy_store::context_assistance_registry::picked::{self, Folder};

pub(super) type Picks = BTreeMap<PathBuf, Folder>;

const PICKER: &str = "dashboard";

impl Engine {
    /// Once per worker, before the first dashboard request and from the
    /// first maintenance pass, so prompts use the picked files too.
    pub(super) fn restore_picked(&mut self, runtime: &mut VerifiedRuntime) {
        if self.picked.is_some() {
            return;
        }
        let saved = picked::load(&self.home).unwrap_or_default();
        let folders = restorable(saved.clone());
        self.picked = Some(folders.clone());
        for folder in folders.clone().into_values() {
            let notes = NotesAccess {
                read: folder.notes_read,
                propose: folder.notes_propose,
            };
            let _ = self.grant(
                runtime,
                folder.workspace,
                PICKER.into(),
                folder.sources,
                notes,
            );
        }
        if folders.values().ne(saved.iter()) {
            self.save_picked();
        }
    }

    /// Records the dashboard pick behind `id` after a grant or a change to
    /// its files. `notes` is `None` when the pick keeps its earlier access.
    pub(super) fn remember_pick(&mut self, id: &str, notes: Option<NotesAccess>) {
        let Some(scope) = self.scopes.get(id) else {
            return;
        };
        if scope.app != PICKER || scope.revoked || self.auto.contains(id) {
            return;
        }
        let workspace = scope.root.path().to_path_buf();
        let mut sources: Vec<String> = (scope.sources.values())
            .map(|source| source.relative_path.clone())
            .collect();
        sources.sort();
        let Some(picks) = self.picked.as_mut() else {
            return;
        };
        let earlier = picks.get(&workspace);
        let notes = notes.unwrap_or_else(|| NotesAccess {
            read: earlier.is_some_and(|folder| folder.notes_read),
            propose: earlier.is_some_and(|folder| folder.notes_propose),
        });
        let folder = Folder {
            workspace: workspace.clone(),
            sources,
            notes_read: notes.read,
            notes_propose: notes.propose,
        };
        if picks.get(&workspace) != Some(&folder) {
            picks.insert(workspace, folder);
            self.save_picked();
        }
    }

    /// The person took the folder back; it is not restored again.
    pub(super) fn forget_pick(&mut self, id: &str) {
        let Some(scope) = self.scopes.get(id).filter(|scope| scope.app == PICKER) else {
            return;
        };
        let workspace = scope.root.path().to_path_buf();
        if self
            .picked
            .as_mut()
            .is_some_and(|picks| picks.remove(&workspace).is_some())
        {
            self.save_picked();
        }
    }

    pub(super) fn forget_picks(&mut self) {
        self.picked = Some(Picks::new());
        self.save_picked();
    }

    /// A failed write leaves the pick working until CIGAR restarts.
    fn save_picked(&self) {
        if let Some(picks) = &self.picked {
            let folders: Vec<Folder> = picks.values().cloned().collect();
            let _ = picked::save(&self.home, &folders);
        }
    }
}

/// A folder that is gone ends its pick, and a file that is gone leaves it,
/// since one missing file would otherwise stop the whole folder coming back.
/// Anything else that stops a restore (a setting turned off, a busy limit)
/// keeps the pick for the next worker.
fn restorable(saved: Vec<Folder>) -> Picks {
    saved
        .into_iter()
        .filter(|folder| folder.workspace.is_dir())
        .map(|mut folder| {
            let root = folder.workspace.clone();
            folder.sources.retain(|source| root.join(source).is_file());
            (folder.workspace.clone(), folder)
        })
        .collect()
}

#[cfg(test)]
#[path = "context_assistance_engine_picked_tests.rs"]
mod tests;
