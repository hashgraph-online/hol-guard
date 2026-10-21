//! Metadata-only preparation behind the authenticated resident factory boundary.
//! Verified authority bytes originate exclusively from the installed/remote
//! factories. Integrity is not activation authority; no pack is read or admitted.
#[path = "catalog_prepare_api.rs"]
mod api;
#[path = "catalog_prepare_buffer.rs"]
mod buffer;
#[path = "catalog_prepare_io.rs"]
mod io;
#[path = "catalog_prepare_proof.rs"]
mod proof;
#[path = "catalog_cache_reader.rs"]
mod reader;
use crate::{
    catalog_read_model::discovery, catalog_read_projection::extension_entry,
    native_command_program::source::PackObjectRef,
};
pub use api::{Action, Handle, Profile, ReadRequest, Request, VerifiedAuthority};
use io::{Result, OBJECT_BYTES};
use proof::{Job, LoadError, Located};
pub(crate) use reader::CacheReader;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

pub const CAPABILITY: &str = "catalog-prepare-v1";
pub const BATCH_CAPABILITY: &str = "catalog-prepare-batch-v1";
#[cfg(test)]
pub(crate) fn read_cache_object(directory: &Path, digest: &str) -> Result<Vec<u8>> {
    io::read(directory, digest)
}
const MAX_EXTENSIONS: usize = 100_000;
const MAX_SESSIONS: usize = 4;
const MAX_HANDLES: usize = 64;

struct Session {
    home: PathBuf,
    token: String,
    authority: String,
    source: String,
    profile: Profile,
    expires_at: Option<u64>,
    count: usize,
    jobs: Vec<Job>,
    pending: Option<Located>,
    batched: bool,
    pending_batch: Vec<Located>,
    fetched: BTreeMap<String, Vec<u8>>,
    rows: BTreeMap<String, PackObjectRef>,
    published: usize,
    next_page: Option<PackObjectRef>,
    permissions: io::Ownership,
}
#[derive(Default)]
struct State {
    sessions: BTreeMap<String, Session>,
    handles: VecDeque<(PathBuf, Handle)>,
}
fn state() -> &'static Mutex<State> {
    static STATE: OnceLock<Mutex<State>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(State::default()))
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "catalog_prepare_clock_invalid")
}
fn fresh(profile: &Profile, expiry: Option<u64>) -> Result<()> {
    match (profile, expiry) {
        (Profile::Installed, None) => Ok(()),
        (Profile::Remote, Some(expiry)) if now()? < expiry => Ok(()),
        _ => Err("catalog_prepare_authority_expired"),
    }
}
impl Session {
    fn begin(home: &Path, authority: VerifiedAuthority) -> Result<Self> {
        fresh(&authority.profile, authority.expires_at)?;
        if authority.data.is_empty()
            || authority.data.len() > OBJECT_BYTES
            || io::hash(&authority.data) != authority.digest
            || authority.source_sha.len() != 40
            || !authority
                .source_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("catalog_prepare_authority_invalid");
        }
        let root = io::json(&authority.data)?;
        let schema = match authority.profile {
            Profile::Installed => "guard.command-pack-bundle.v1",
            Profile::Remote => "guard.extension-distribution.v2",
        };
        if root["schema"] != schema
            || root["source_sha"] != authority.source_sha
            || (authority.profile == Profile::Remote
                && root["expires_at"].as_u64() != authority.expires_at)
            || (authority.profile == Profile::Installed && root.get("expires_at").is_some())
        {
            return Err("catalog_prepare_authority_invalid");
        }
        let native = &root["policy"]["root"];
        let count = native["extensions"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .ok_or("catalog_prepare_count_invalid")?;
        if count == 0
            || count > MAX_EXTENSIONS
            || native["schema"] != "guard.command-pack-release.v1"
            || native["engine"] != root["engine"]
        {
            return Err("catalog_prepare_count_invalid");
        }
        let expected = proof::reference(&native["index"])?;
        if expected.kind != "data" {
            return Err("catalog_prepare_index_invalid");
        }
        let source = if authority.profile == Profile::Installed {
            authority.source_sha.clone()
        } else {
            String::new()
        };
        let transport = proof::located(&root["policy"]["transport"], &source)?;
        if transport.kind != "data" {
            return Err("catalog_prepare_transport_invalid");
        }
        // Check every ancestor before creating a private native-runtime parent.
        io::private_directory(&home.join("native-runtime"))?;
        let directory = home.join("native-runtime/catalog-discovery");
        io::private_directory(&directory)?;
        io::private_directory(&directory.join("objects"))?;
        io::private_directory(&directory.join("transport"))?;
        let token = io::nonce()?;
        let permissions =
            io::Ownership::new(directory.join(format!("preparation-{token}")), count)?;
        Ok(Self {
            home: home.into(),
            token,
            authority: authority.digest,
            source,
            profile: authority.profile,
            expires_at: authority.expires_at,
            count,
            jobs: vec![Job::Transport(transport, expected, count, String::new())],
            pending: None,
            batched: false,
            pending_batch: Vec::new(),
            fetched: BTreeMap::new(),
            rows: BTreeMap::new(),
            published: 0,
            next_page: None,
            permissions,
        })
    }

    fn directory(&self, name: &str) -> PathBuf {
        self.home
            .join("native-runtime/catalog-discovery")
            .join(name)
    }

    fn drive(&mut self) -> Result<Option<Handle>> {
        let reader = CacheReader::new(&self.directory("transport"))?;
        let writer = CacheReader::new(&self.directory("objects"))?;
        let result = self.drive_reader(&reader, &writer);
        reader.finish()?;
        writer.finish()?;
        result
    }

    fn drive_reader(
        &mut self,
        reader: &CacheReader,
        writer: &CacheReader,
    ) -> Result<Option<Handle>> {
        fresh(&self.profile, self.expires_at)?;
        let mut work = 0;
        let mut bytes = 0;
        let mut deferred = Vec::new();
        while let Some(job) = self.jobs.last() {
            if work == 64 || (work > 0 && bytes + job.target().expanded_length > io::BLOB_BYTES) {
                break;
            }
            work += 1;
            bytes += job.target().expanded_length;
            if matches!(job, Job::Transport(..) | Job::Index(..)) && job.target().kind != "data" {
                return Err("catalog_prepare_page_budget");
            }
            let data = match proof::load(reader, job.target(), &self.source, 0, &self.fetched) {
                Ok(data) => data,
                Err(LoadError::Missing(target)) => {
                    let target = *target;
                    if self.batched {
                        if !self.pending_batch.iter().any(|p| p.sha256 == target.sha256) {
                            self.pending_batch.push(target);
                        }
                        deferred.push(self.jobs.pop().ok_or("catalog_prepare_session_invalid")?);
                        if self.pending_batch.len() == 64 {
                            break;
                        }
                        continue;
                    }
                    self.pending = Some(target);
                    return Ok(None);
                }
                Err(LoadError::Invalid(error)) => return Err(error),
            };
            let value = io::json(&data)?;
            let job = self.jobs.pop().ok_or("catalog_prepare_session_invalid")?;
            self.fetched.remove(&job.target().sha256);
            match job {
                Job::Transport(_, expected, count, prefix) => self.jobs.push(proof::transport(
                    value,
                    &expected,
                    count,
                    &prefix,
                    &self.source,
                )?),
                Job::Index(_, wrapper, count, prefix) => {
                    let jobs = proof::index(&value, &wrapper, count, &prefix, &self.source)?;
                    self.jobs.extend(jobs.into_iter().rev());
                }
                Job::Record(_, id, manifest) => {
                    self.jobs
                        .push(proof::record(&value, &id, &manifest, &self.source)?)
                }
                Job::Metadata(_, id) => self.metadata(value, id, writer)?,
            }
        }
        self.jobs.extend(deferred.into_iter().rev());
        if !self.jobs.is_empty() {
            return Ok(None);
        }
        fresh(&self.profile, self.expires_at)?;
        if self.rows.len() != self.count {
            return Err("catalog_prepare_incomplete");
        }
        // Retain only compact identity/reference rows; payloads are already CAS.
        if self.published < self.count {
            let mut chunk: Vec<_> = self
                .rows
                .iter()
                .rev()
                .skip(self.published)
                .take(64)
                .collect();
            self.published += chunk.len();
            chunk.reverse();
            let page = writer.put_json(
                &json!({"schema":"guard.catalog-discovery-page.v1","entries":chunk,"next":self.next_page}),
            )?;
            if page.kind != "data" {
                return Err("catalog_prepare_page_budget");
            }
            self.next_page = Some(page);
            return Ok(None);
        }
        let root = writer.put_json(
            &json!({"schema":"guard.catalog-discovery.v1","authority":self.authority,"count":self.count,"first":self.next_page}),
        )?;
        fresh(&self.profile, self.expires_at)?;
        Ok(Some(Handle {
            root: root.sha256,
            authority: self.authority.clone(),
            token: io::nonce()?,
            profile: self.profile.clone(),
            expires_at: self.expires_at,
        }))
    }

    fn metadata(&mut self, value: Value, id: String, writer: &CacheReader) -> Result<()> {
        let values = value.as_array().ok_or("catalog_prepare_metadata_invalid")?;
        if values.len() != 1 {
            return Err("catalog_prepare_metadata_invalid");
        }
        let value = &values[0];
        if value["extension_id"] != id
            || self.rows.contains_key(&id)
            || self.rows.len() >= self.count
        {
            return Err("catalog_prepare_duplicate_identity");
        }
        let entry = extension_entry(value)?;
        if value["permission_count"].as_u64() != Some(entry.permissions.len() as u64)
            || value["rule_count"].as_u64() != Some(entry.rules.len() as u64)
            || crate::catalog_read_query::CatalogRoute::parse(&format!("extensions/{id}")).is_err()
        {
            return Err("catalog_prepare_metadata_invalid");
        }
        for permission in value["permissions"]
            .as_array()
            .ok_or("catalog_prepare_metadata_invalid")?
        {
            let target = permission["permission_id"]
                .as_str()
                .ok_or("catalog_prepare_metadata_invalid")?;
            if permission["extension_id"] != id {
                return Err("catalog_prepare_permission_ownership");
            }
            self.permissions.claim(target)?;
        }
        drop(entry);
        self.rows.insert(id, writer.put_json(value)?);
        Ok(())
    }
}

fn validate(state: &State, home: &Path, handle: &Handle) -> Result<()> {
    fresh(&handle.profile, handle.expires_at)?;
    if !state
        .handles
        .iter()
        .any(|(h, saved)| h == home && saved == handle)
    {
        return Err("catalog_prepare_handle_invalid");
    }
    let directory = home.join("native-runtime/catalog-discovery/objects");
    let root = io::json(&io::read(&directory, &handle.root)?)?;
    if root["authority"] != handle.authority {
        return Err("catalog_prepare_handle_invalid");
    }
    Ok(())
}

pub fn evaluate(request: Request) -> Value {
    match execute(request) {
        Ok(value) => value,
        Err(error) => {
            json!({"schema":"guard.catalog-prepare-result.v1","outcome":"error","error_code":error})
        }
    }
}
fn execute(request: Request) -> Result<Value> {
    let mut state = state()
        .lock()
        .map_err(|_| "catalog_prepare_state_unavailable")?;
    let home = request.guard_home;
    if !home.is_absolute() {
        return Err("catalog_prepare_home_invalid");
    }
    let batched = matches!(&request.action, Action::BeginBatched { .. });
    let mut session = match request.action {
        Action::Begin { authority } | Action::BeginBatched { authority } => {
            state.sessions.retain(|_, s| s.home != home);
            if state.sessions.len() >= MAX_SESSIONS {
                return Err("catalog_prepare_session_budget");
            }
            let mut session = Session::begin(&home, authority)?;
            session.batched = batched;
            session
        }
        Action::AdvanceBatch { session, data } => {
            if state.sessions.get(&session).is_none_or(|s| s.home != home) {
                return Err("catalog_prepare_session_invalid");
            }
            let mut session = state
                .sessions
                .remove(&session)
                .ok_or("catalog_prepare_session_invalid")?;
            fresh(&session.profile, session.expires_at)?;
            if !session.batched
                || data.is_empty()
                || data.len() > 64
                || data.len() != session.pending_batch.len()
            {
                return Err("catalog_prepare_batch_invalid");
            }
            for (data, expected) in data.iter().zip(&session.pending_batch) {
                if data.len() != expected.length || io::hash(data) != expected.sha256 {
                    return Err("catalog_prepare_fetch_integrity");
                }
            }
            for data in data {
                session.buffer_fetched(data)?;
            }
            session.pending_batch.clear();
            session
        }
        Action::Advance { session, data } => {
            // A wrong home cannot remove or advance another session.
            if state.sessions.get(&session).is_none_or(|s| s.home != home) {
                return Err("catalog_prepare_session_invalid");
            }
            let mut session = state
                .sessions
                .remove(&session)
                .ok_or("catalog_prepare_session_invalid")?;
            fresh(&session.profile, session.expires_at)?;
            let expected = session
                .pending
                .take()
                .ok_or("catalog_prepare_session_invalid")?;
            if data.len() != expected.length || io::hash(&data) != expected.sha256 {
                return Err("catalog_prepare_fetch_integrity");
            }
            io::put(&session.directory("transport"), &data, "data", data.len())?;
            session.fetched.clear();
            session.fetched.insert(expected.sha256, data);
            session
        }
        Action::Resume { session } => {
            if state.sessions.get(&session).is_none_or(|s| s.home != home) {
                return Err("catalog_prepare_session_invalid");
            }
            let session = state
                .sessions
                .remove(&session)
                .ok_or("catalog_prepare_session_invalid")?;
            if session.pending.is_some() || !session.pending_batch.is_empty() {
                return Err("catalog_prepare_fetch_required");
            }
            session
        }
        Action::Validate { handle } => {
            validate(&state, &home, &handle)?;
            return Ok(
                json!({"schema":"guard.catalog-prepare-result.v1","outcome":"valid","handle":handle}),
            );
        }
        Action::Abort { session } => {
            if state.sessions.get(&session).is_none_or(|s| s.home != home) {
                return Err("catalog_prepare_session_invalid");
            }
            state.sessions.remove(&session);
            return Ok(json!({"schema":"guard.catalog-prepare-result.v1","outcome":"aborted"}));
        }
    };
    if let Some(handle) = session.drive()? {
        state
            .handles
            .retain(|(_, saved)| fresh(&saved.profile, saved.expires_at).is_ok());
        if state.handles.len() == MAX_HANDLES {
            state.handles.pop_front();
        }
        state.handles.push_back((home, handle.clone()));
        Ok(json!({"schema":"guard.catalog-prepare-result.v1","outcome":"complete","handle":handle}))
    } else {
        let result = if !session.pending_batch.is_empty() {
            json!({"schema":"guard.catalog-prepare-result.v1","outcome":"fetch_batch","session":session.token,"fetches":session.pending_batch})
        } else if session.pending.is_some() {
            json!({"schema":"guard.catalog-prepare-result.v1","outcome":"fetch","session":session.token,"fetch":session.pending})
        } else {
            json!({"schema":"guard.catalog-prepare-result.v1","outcome":"continue","session":session.token})
        };
        state.sessions.insert(session.token.clone(), session);
        Ok(result)
    }
}

pub fn read(request: &ReadRequest) -> crate::catalog_read_model::CatalogReadResultV1 {
    let valid = state()
        .lock()
        .ok()
        .is_some_and(|state| validate(&state, &request.guard_home, &request.handle).is_ok());
    if !valid {
        return crate::catalog_read_model::read_result(
            Err(crate::catalog_read_model::CatalogReadError::Unavailable),
            &request.read,
        );
    }
    let result = discovery::evaluate(&discovery::CatalogReadRequestV2 {
        guard_home: request.guard_home.clone(),
        discovery_root: request.handle.root.clone(),
        read: request.read.clone(),
    });
    if fresh(&request.handle.profile, request.handle.expires_at).is_err() {
        return crate::catalog_read_model::read_result(
            Err(crate::catalog_read_model::CatalogReadError::Unavailable),
            &request.read,
        );
    }
    result
}

#[cfg(test)]
#[path = "catalog_prepare_tests.rs"]
mod tests;
