//! Automatic project context for agent prompts.
//!
//! When someone has turned on agent context, each prompt an agent hook sees
//! keeps one memory-only scope per (project, app) up to date with the files
//! that prompt is about, and asks CIGAR which parts matter. A project picked
//! by hand always wins, for every app when it was picked in the dashboard:
//! its files stay exactly as chosen. Automatic scopes
//! never keep a resting worker awake and are the first to make room.
use super::*;
use std::time::{Instant, SystemTime};

#[path = "context_assistance_engine_quick.rs"]
mod quick;
pub(crate) use quick::{
    definition, opened, project_context_on, prose, quick_excerpts, screened_texts, withheld_texts,
};

/// The graph holds 128 sources, Guard's own included, and a removed file
/// still counts until the graph is rebuilt.
const MAX_SOURCES: usize = 96;
const MAX_SLOTS: usize = 120;
/// Files read into the graph per prompt, so one call stays well inside the
/// actor deadline.
const MAX_NEW: usize = 24;
const MAX_BYTES: usize = 3 * 1024 * 1024;

#[derive(Default)]
pub(super) struct AutoScopes(BTreeMap<String, Auto>);

struct Auto {
    used: Instant,
    stamps: BTreeMap<String, Stamp>,
    retired: usize,
}

#[derive(Clone, Copy, PartialEq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
}

impl AutoScopes {
    pub(super) fn contains(&self, id: &str) -> bool {
        self.0.contains_key(id)
    }
}

/// One excerpt CIGAR picked, named by the project file it came from.
pub(crate) struct PickedExcerpt {
    pub(crate) path: String,
    pub(crate) start_line: u64,
    pub(crate) end_line: u64,
    pub(crate) text: String,
}

fn stamp(root: &SourceRoot, relative: &str) -> Option<Stamp> {
    let metadata = std::fs::symlink_metadata(root.path().join(relative)).ok()?;
    metadata.is_file().then(|| Stamp {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn bytes(file: &AdmittedFile) -> usize {
    file.documents.iter().map(|doc| doc.text.len()).sum()
}

/// CIGAR's picks, led by the walk's best file when CIGAR left it out. The walk
/// ranks files by the prompt's exact words and quoted text, which a pick by
/// meaning can miss, so the file the prompt names comes first with the chunk
/// that holds the most of `words`, the walk's own words and quoted text from
/// the whole prompt. A file whose chunks share none of them is not added.
///
/// When CIGAR did pick that file but none of its picks overlaps that chunk,
/// the chunk still leads unless a pick of the file holds more of `words`: a
/// pick by meaning can land on the file's neighbouring lines and leave out
/// the ones the prompt quotes.
fn led_by(
    mut picked: Vec<PickedExcerpt>,
    lead: Option<&AdmittedFile>,
    words: &[String],
) -> Vec<PickedExcerpt> {
    let Some((score, part)) = lead.and_then(|file| quick::best_part(file, words)) else {
        return picked;
    };
    let of_file = || picked.iter().filter(|excerpt| excerpt.path == part.path);
    let covered = of_file()
        .any(|excerpt| excerpt.start_line <= part.end_line && excerpt.end_line >= part.start_line);
    if covered || of_file().any(|excerpt| quick::said(&excerpt.text, words) > score) {
        return picked;
    }
    picked.insert(0, part);
    picked
}

/// Reads the wanted files that are not in the scope yet. A file the source
/// screen refuses (a secret, a key, binary text) is simply left out.
fn admit(
    root: &SourceRoot,
    wanted: &[String],
    have: &BTreeMap<String, AdmittedFile>,
    room: usize,
) -> Vec<(AdmittedFile, Stamp)> {
    let mut total: usize = have.values().map(bytes).sum();
    let mut admitted = Vec::new();
    for relative in wanted {
        if admitted.len() >= room.min(MAX_NEW) {
            break;
        }
        if have.values().any(|file| &file.relative_path == relative) {
            continue;
        }
        let (Some(stamp), Ok(file)) = (stamp(root, relative), root.read(relative)) else {
            continue;
        };
        if total + bytes(&file) > MAX_BYTES {
            continue;
        }
        total += bytes(&file);
        admitted.push((file, stamp));
    }
    admitted
}

impl Engine {
    /// Picks context for one agent prompt in `workspace`. `Ok(None)` means
    /// nothing in the project matched, so the prompt gets nothing added.
    pub(crate) fn prompt_context(
        &mut self,
        runtime: &mut VerifiedRuntime,
        workspace: PathBuf,
        app: String,
        wanted: Vec<String>,
        query: String,
        words: &[String],
    ) -> Result<Option<Vec<PickedExcerpt>>, RuntimeError> {
        if crate::guard_config_harness::canonical_harness_id(&app) != Some(app.as_str()) {
            return Err(RuntimeError::ScopeDenied);
        }
        let root = SourceRoot::inspect(&workspace)?;
        if root.path().starts_with(&self.home) {
            return Err(RuntimeError::ScopeDenied);
        }
        self.forget_closed_auto(runtime);
        let same = |scope: &Scope| scope.root.path() == root.path() && scope.app == app;
        if let Some(id) = self
            .scopes
            .iter()
            .filter(|(id, scope)| {
                !self.auto.contains(id) && !scope.revoked && scope.root.path() == root.path()
            })
            .filter_map(|(id, scope)| Some((pick_rank(&scope.app, &app, scope.sources.len())?, id)))
            .min_by_key(|(rank, _)| *rank)
            .map(|(_, id)| id.clone())
        {
            return self.pick(runtime, &id, &query).map(Some);
        }
        let existing = self
            .scopes
            .iter()
            .find(|(id, scope)| self.auto.contains(id) && same(scope))
            .map(|(id, _)| id.clone());
        let id = match existing {
            Some(id) if self.sync_auto(runtime, &id, &wanted)? => id,
            Some(id) => {
                self.drop_scope(runtime, &id)?;
                match self.open_auto(runtime, root, app, &wanted)? {
                    Some(id) => id,
                    None => return Ok(None),
                }
            }
            None => match self.open_auto(runtime, root, app, &wanted)? {
                Some(id) => id,
                None => return Ok(None),
            },
        };
        let picked = self.pick(runtime, &id, &query)?;
        let lead = wanted.first().and_then(|first| {
            let scope = self.scopes.get(&id)?;
            scope
                .sources
                .values()
                .find(|file| &file.relative_path == first)
        });
        Ok(Some(led_by(picked, lead, words)))
    }

    /// Records this worker's hand picks for prompts Guard reads itself.
    pub(super) fn publish_hands(&self) {
        let picked = (self.scopes.iter())
            .filter(|(id, scope)| !self.auto.contains(id) && !scope.revoked)
            .map(|(_, scope)| quick::Hand {
                root: scope.root.path().to_path_buf(),
                app: scope.app.clone(),
                files: (scope.sources.values())
                    .map(|file| file.relative_path.clone())
                    .collect(),
            })
            .collect();
        quick::publish(&self.home, picked);
    }

    /// Before a hand-picked grant: drop the automatic scope for the same
    /// project and app, then free a slot from the least recently used one.
    pub(super) fn make_room(
        &mut self,
        runtime: &mut VerifiedRuntime,
        workspace: &std::path::Path,
        app: &str,
    ) -> Result<(), RuntimeError> {
        if let Ok(root) = SourceRoot::inspect(workspace) {
            let twin = self
                .scopes
                .iter()
                .find(|(id, scope)| {
                    self.auto.contains(id) && scope.root.path() == root.path() && scope.app == app
                })
                .map(|(id, _)| id.clone());
            if let Some(id) = twin {
                self.drop_scope(runtime, &id)?;
            }
        }
        while self.scopes.len() >= self.limits.max_active_workspaces as usize {
            if !self.evict_oldest_auto(runtime)? {
                break;
            }
        }
        Ok(())
    }

    fn open_auto(
        &mut self,
        runtime: &mut VerifiedRuntime,
        root: SourceRoot,
        app: String,
        wanted: &[String],
    ) -> Result<Option<String>, RuntimeError> {
        let policy = effective(&self.home, &root)?;
        if !policy.features.agent_context || !policy.sources.workspace_documents {
            return Err(RuntimeError::ScopeDenied);
        }
        let admitted = admit(&root, wanted, &BTreeMap::new(), MAX_NEW);
        if admitted.is_empty() {
            return Ok(None);
        }
        let limit = self
            .limits
            .max_active_workspaces
            .min(policy.limits.max_active_workspaces) as usize;
        while self.scopes.len() >= limit {
            if !self.evict_oldest_auto(runtime)? {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        let mut stamps = BTreeMap::new();
        let mut sources = BTreeMap::new();
        for (file, stamp) in admitted {
            stamps.insert(file.source_id.clone(), stamp);
            sources.insert(file.source_id.clone(), file);
        }
        let id = self.admit_scope(runtime, root, app, policy, sources, NotesAccess::default())?;
        let auto = Auto {
            used: Instant::now(),
            stamps,
            retired: 0,
        };
        self.auto.0.insert(id.clone(), auto);
        Ok(Some(id))
    }

    /// Brings an automatic scope up to date: rereads files that changed,
    /// drops ones that are gone or now refused, and adds the prompt's new
    /// files. `false` means the graph is full and should be rebuilt.
    fn sync_auto(
        &mut self,
        runtime: &mut VerifiedRuntime,
        id: &str,
        wanted: &[String],
    ) -> Result<bool, RuntimeError> {
        let (Some(scope), Some(auto)) = (self.scopes.get_mut(id), self.auto.0.get_mut(id)) else {
            return Err(RuntimeError::ScopeDenied);
        };
        policy_current(&self.home, scope, runtime)?;
        let mut changed = false;
        let mut removed = false;
        let current: Vec<(String, String)> = scope
            .sources
            .values()
            .map(|file| (file.source_id.clone(), file.relative_path.clone()))
            .collect();
        for (source_id, relative) in current {
            let now = stamp(&scope.root, &relative);
            if now.is_some() && now == auto.stamps.get(&source_id).copied() {
                continue;
            }
            match (now, scope.root.read(&relative)) {
                (Some(now), Ok(fresh)) => {
                    scope
                        .graph
                        .replace_source(runtime, &source_id, fresh.documents.clone())?;
                    auto.stamps.insert(source_id.clone(), now);
                    scope.sources.insert(source_id, fresh);
                }
                _ => {
                    scope
                        .graph
                        .replace_source(runtime, &source_id, Vec::new())?;
                    auto.stamps.remove(&source_id);
                    scope.sources.remove(&source_id);
                    auto.retired += 1;
                    removed = true;
                }
            }
            changed = true;
        }
        let missing = wanted
            .iter()
            .filter(|relative| {
                !scope
                    .sources
                    .values()
                    .any(|f| &f.relative_path == *relative)
            })
            .count();
        let room = MAX_SOURCES.saturating_sub(scope.sources.len());
        if missing > room || scope.sources.len() + auto.retired + missing.min(MAX_NEW) > MAX_SLOTS {
            return Ok(false);
        }
        for (file, now) in admit(&scope.root, wanted, &scope.sources, room) {
            scope
                .graph
                .replace_source(runtime, &file.source_id, file.documents.clone())?;
            auto.stamps.insert(file.source_id.clone(), now);
            scope.sources.insert(file.source_id.clone(), file);
            changed = true;
        }
        if changed {
            scope.clear_contexts();
            let allowed = allowed(&scope.sources, &scope.policy);
            if removed {
                scope.graph.narrow_sources(runtime, allowed.clone())?;
            }
            scope
                .graph
                .create_view(runtime, "app", allowed, &scope.revision, false)?;
        }
        auto.used = Instant::now();
        Ok(true)
    }

    fn pick(
        &mut self,
        runtime: &mut VerifiedRuntime,
        id: &str,
        query: &str,
    ) -> Result<Vec<PickedExcerpt>, RuntimeError> {
        let automatic = self.auto.contains(id);
        let scope = self.scopes.get_mut(id).ok_or(RuntimeError::ScopeDenied)?;
        policy_current(&self.home, scope, runtime)?;
        if !automatic {
            current_sources(scope)?;
        }
        scope.reserve_context();
        let context = scope
            .graph
            .compile(runtime, "app", query, Vec::new(), None)?;
        policy_current(&self.home, scope, runtime)?;
        let brief = context.brief().clone();
        let dependencies = context.dependencies(runtime)?;
        scope.contexts.insert(brief.snapshot_id.clone(), context);
        scope.history.expire(scope.policy.storage.retention_hours);
        scope.history.record_with_dependencies(
            brief.clone(),
            &scope.sources,
            None,
            &runtime.status().package_version,
            &runtime.status().worker_fingerprint,
            &dependencies,
        );
        let paths: BTreeMap<&str, &str> = scope
            .sources
            .values()
            .map(|file| (file.source_id.as_str(), file.relative_path.as_str()))
            .collect();
        Ok(brief
            .excerpts
            .iter()
            .filter_map(|excerpt| {
                let citation = excerpt.citations.first()?;
                Some(PickedExcerpt {
                    path: (*paths.get(citation["source"].as_str()?)?).to_owned(),
                    start_line: citation["start_line"].as_u64()?,
                    end_line: citation["end_line"].as_u64()?,
                    text: excerpt.text.clone(),
                })
            })
            .collect())
    }

    fn evict_oldest_auto(&mut self, runtime: &mut VerifiedRuntime) -> Result<bool, RuntimeError> {
        let Some(id) = self
            .auto
            .0
            .iter()
            .min_by_key(|(_, auto)| auto.used)
            .map(|(id, _)| id.clone())
        else {
            return Ok(false);
        };
        self.drop_scope(runtime, &id)?;
        Ok(true)
    }

    fn drop_scope(&mut self, runtime: &mut VerifiedRuntime, id: &str) -> Result<(), RuntimeError> {
        self.auto.0.remove(id);
        if let Some(mut scope) = self.scopes.remove(id) {
            scope.clear_contexts();
            close_graph(runtime, &mut scope.graph)?;
        }
        Ok(())
    }

    /// Settings changes and expired saved copies close a scope in place;
    /// an automatic one is rebuilt on the next prompt instead.
    fn forget_closed_auto(&mut self, runtime: &mut VerifiedRuntime) {
        let scopes = &self.scopes;
        self.auto.0.retain(|id, _| scopes.contains_key(id));
        let closed: Vec<String> = self
            .auto
            .0
            .keys()
            .filter(|id| self.scopes[*id].revoked)
            .cloned()
            .collect();
        for id in closed {
            self.auto.0.remove(&id);
            if let Some(mut scope) = self.scopes.remove(&id) {
                let _ = scope.graph.close(runtime);
            }
        }
    }
}

/// How a project picked by hand answers `app`'s prompts: a pick for that app
/// comes first, then files picked in the dashboard, which serve every app.
/// A dashboard pick of no files leaves the prompt to the automatic scope.
fn pick_rank(picked_for: &str, app: &str, files: usize) -> Option<u8> {
    if picked_for == app {
        Some(0)
    } else if picked_for == "dashboard" && files > 0 {
        Some(1)
    } else {
        None
    }
}

#[cfg(test)]
#[path = "context_assistance_engine_lead_tests.rs"]
mod lead_tests;
