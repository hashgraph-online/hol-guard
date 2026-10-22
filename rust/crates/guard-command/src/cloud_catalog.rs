//! Complete Cloud metadata producer. Never changes enforcement or activation.
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tempfile::TempDir;

#[path = "cloud_catalog_cache.rs"]
mod cache;
#[path = "cloud_catalog_completion.rs"]
pub mod completion;
#[path = "cloud_catalog_discovery.rs"]
mod discovery;
#[path = "cloud_catalog_policy.rs"]
mod policy;
#[path = "cloud_catalog_policy_view.rs"]
mod policy_view;
#[path = "cloud_catalog_projection.rs"]
mod projection;
#[path = "cloud_catalog_sync.rs"]
pub mod sync;
#[path = "cloud_catalog_wire_v1.rs"]
pub mod wire_v1;
pub use policy::select_policy_metadata;
#[cfg(test)]
#[path = "cloud_catalog_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "cloud_catalog_wire_v1_sync_tests.rs"]
mod wire_v1_sync_tests;
#[cfg(test)]
#[path = "cloud_catalog_wire_v1_tests.rs"]
mod wire_v1_tests;

pub const CAPABILITY: &str = "cloud-catalog-producer-v2";
pub const MAX_ENTRY: usize = 1_000_000;
pub const MAX_PAGE_ENTRIES: usize = 64;
pub const MAX_PAGE: usize = 2 * 1024 * 1024;
pub const MAX_PAGES: usize = 8192;
pub const MAX_TOTAL: usize = 512 * 1024 * 1024;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Invalid,
    Limit,
    Unavailable,
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Unavailable
    }
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Invalid
    }
}
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::Invalid)
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn digest(value: &Value) -> Result<String> {
    Ok(hash(&encode(value)?))
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub guard_home: PathBuf,
    pub discovery_root: String,
    pub discovery_authority: String,
    pub enforcement_catalog_digest: String,
    pub guard_version: String,
    pub generated_at: String,
}
impl Observation {
    fn validate(&self) -> Result<()> {
        if !self.guard_home.is_absolute()
            || !sha(&self.discovery_root)
            || !sha(&self.discovery_authority)
            || !sha(&self.enforcement_catalog_digest)
            || self.guard_version.is_empty()
            || self.guard_version.chars().count() > 128
            || !timestamp(&self.generated_at)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
fn timestamp(s: &str) -> bool {
    // Same strict Gregorian RFC3339 timestamp contract as Cloud. ASCII digits
    // only: `\d` would admit any Unicode decimal digit.
    let re = regex::Regex::new(
        r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?(Z|[+-]([0-9]{2}):([0-9]{2}))$",
    )
    .unwrap();
    let Some(c) = re.captures(s) else {
        return false;
    };
    let n = |i| {
        c.get(i)
            .and_then(|s| s.as_str().parse::<u32>().ok())
            .unwrap_or(0)
    };
    let y = n(1);
    let m = n(2);
    let d = n(3);
    let days = match m {
        2 => 28 + u32::from(y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)),
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    s.len() <= 128
        && y > 0
        && d > 0
        && d <= days
        && n(4) < 24
        && n(5) < 60
        && n(6) < 60
        && n(8) < 24
        && n(9) < 60
}

pub struct Builder {
    observation: Observation,
    spool: TempDir,
    db: Connection,
    active_count: usize,
    active_bytes: usize,
    lease: std::fs::File,
}
impl Builder {
    pub fn new(observation: Observation) -> Result<Self> {
        observation.validate()?;
        let directory = cache::directory(&observation.guard_home)?;
        let (spool, lease) = cache::draft(&directory)?;
        let db = Connection::open(spool.path().join("index.sqlite"))?;
        db.execute_batch(
            "PRAGMA cache_size=-1024; PRAGMA journal_mode=OFF; PRAGMA temp_store=FILE;
            PRAGMA max_page_count=131072;
            CREATE TABLE entries(id TEXT PRIMARY KEY, value TEXT, active INTEGER) WITHOUT ROWID;
            CREATE TABLE permissions(id TEXT PRIMARY KEY) WITHOUT ROWID;
            CREATE TABLE replacements(id TEXT PRIMARY KEY, target TEXT) WITHOUT ROWID; BEGIN;",
        )?;
        Ok(Self {
            observation,
            spool,
            db,
            active_count: 0,
            active_bytes: 0,
            lease,
        })
    }
    pub fn append(&mut self, raw: &Value) -> Result<()> {
        let value = projection::project(raw)?;
        self.active_count += 1;
        self.active_bytes += encode(&value)?.len();
        if self.active_count > 100_000 || self.active_bytes > MAX_TOTAL {
            return Err(Error::Limit);
        }
        self.insert(value, true)
    }
    fn insert(&self, value: Value, active: bool) -> Result<()> {
        let id = value["id"].as_str().ok_or(Error::Invalid)?;
        if active {
            self.db.execute(
                "INSERT INTO entries VALUES (?1,?2,1)",
                params![
                    id,
                    String::from_utf8(encode(&value)?).map_err(|_| Error::Invalid)?
                ],
            )?;
        } else {
            self.db.execute(
                "INSERT INTO entries VALUES (?1,?2,0) ON CONFLICT(id) DO NOTHING",
                params![
                    id,
                    String::from_utf8(encode(&value)?).map_err(|_| Error::Invalid)?
                ],
            )?;
        }
        Ok(())
    }
    pub fn finish(self) -> Result<Value> {
        discovery::visit(&self.observation, |entry| self.insert(entry, false))?;
        self.publish()
    }
    fn publish(self) -> Result<Value> {
        let mut query = self.db.prepare("SELECT value FROM entries ORDER BY id")?;
        let mut rows = query.query([])?;
        let mut pending = Vec::new();
        let mut hashes = Vec::new();
        let mut previous = Value::Null;
        let mut count = 0;
        let mut total = 0;
        while let Some(row) = rows.next()? {
            let entry: Value =
                serde_json::from_str(&row.get::<_, String>(0)?).map_err(|_| Error::Invalid)?;
            for permission in entry["permissions"].as_array().ok_or(Error::Invalid)? {
                self.db.execute(
                    "INSERT INTO permissions VALUES (?1)",
                    [permission["id"].as_str().ok_or(Error::Invalid)?],
                )?;
            }
            if let Some(target) = entry["replacementId"].as_str() {
                self.db.execute(
                    "INSERT INTO replacements VALUES (?1,?2)",
                    params![entry["id"].as_str(), target],
                )?;
            }
            pending.push(entry);
            if pending.len() > 64
                || encode(&page(&pending, hashes.len(), &previous)?)?.len() > MAX_PAGE
            {
                let last = pending.pop().ok_or(Error::Invalid)?;
                flush(
                    self.spool.path(),
                    &mut pending,
                    &mut hashes,
                    &mut previous,
                    &mut total,
                )?;
                pending.push(last);
            }
            count += 1;
        }
        if !pending.is_empty() {
            flush(
                self.spool.path(),
                &mut pending,
                &mut hashes,
                &mut previous,
                &mut total,
            )?;
        }
        if count == 0 {
            return Err(Error::Invalid);
        }
        let missing: i64 = self.db.query_row("SELECT count(*) FROM replacements r LEFT JOIN entries e ON r.target=e.id WHERE e.id IS NULL",[],|r|r.get(0))?;
        if missing != 0 {
            return Err(Error::Invalid);
        }
        let completion = json!({"schemaVersion":"guard.extension-catalog-view.v2","pageCount":hashes.len(),
            "extensionCount":count,"lastPageDigest":previous});
        let manifest = json!({"schemaVersion":"guard.extension-catalog.v2","catalogDigest":digest(&completion)?,
            "enforcementCatalogDigest":self.observation.enforcement_catalog_digest,"pageCount":hashes.len(),
            "extensionCount":count,"lastPageDigest":previous,"guardVersion":self.observation.guard_version,
            "controlSchemaVersion":"guard.extension-controls.v1","generatedAt":self.observation.generated_at});
        let record = json!({"manifest":manifest,"hashes":hashes,"observation":self.observation,"totalBytes":total});
        drop(rows);
        drop(query);
        drop(self.db);
        std::fs::remove_file(self.spool.path().join("index.sqlite"))?;
        cache::publish(self.spool, self.lease, record)
    }
}
fn page(entries: &[Value], ordinal: usize, previous: &Value) -> Result<Value> {
    let mut body = json!({"schemaVersion":"guard.extension-catalog-page.v2","ordinal":ordinal,
        "previousDigest":previous,"entries":entries});
    body["pageDigest"] = json!(digest(&body)?);
    Ok(body)
}
fn flush(
    path: &Path,
    pending: &mut Vec<Value>,
    hashes: &mut Vec<String>,
    previous: &mut Value,
    total: &mut usize,
) -> Result<()> {
    let page = page(pending, hashes.len(), previous)?;
    let bytes = encode(&page)?;
    *total += bytes.len();
    if pending.is_empty()
        || hashes.len() >= MAX_PAGES
        || *total > MAX_TOTAL
        || bytes.len() > MAX_PAGE
    {
        return Err(Error::Limit);
    }
    cache::write(&path.join(format!("{}.json", hashes.len())), &bytes)?;
    hashes.push(hash(&bytes));
    *previous = page["pageDigest"].clone();
    pending.clear();
    Ok(())
}

/// Shared CLI/resident interface. Drafts are bounded, private, and never visible
/// as complete. Errors discard the draft; process restart requires preparation.
pub fn evaluate(request: &Value) -> Value {
    if request["action"] == "policy_view" {
        return policy_view::evaluate(request);
    }
    // Stateless Cloud v1 wire projection/validation/digest; no guard home state.
    if request["action"]
        .as_str()
        .is_some_and(|action| action.starts_with("v1_"))
    {
        return wire_v1::evaluate(request);
    }
    static DRAFTS: OnceLock<Mutex<Vec<(String, Builder)>>> = OnceLock::new();
    let result = (|| -> Result<Value> {
        let action = request["action"].as_str().ok_or(Error::Invalid)?;
        if action.starts_with("completion_") {
            return completion::evaluate(request);
        }
        if action == "begin" {
            let observation: Observation = serde_json::from_value(request["observation"].clone())
                .map_err(|_| Error::Invalid)?;
            let builder = Builder::new(observation)?;
            let token = builder
                .spool
                .path()
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(Error::Invalid)?
                .to_owned();
            let mut drafts = DRAFTS
                .get_or_init(Default::default)
                .lock()
                .map_err(|_| Error::Unavailable)?;
            if drafts.len() >= 4 {
                drafts.remove(0);
            }
            drafts.push((token.clone(), builder));
            return Ok(json!({"draft":token}));
        }
        if action == "append" || action == "finish" || action == "abort" {
            let mut drafts = DRAFTS
                .get_or_init(Default::default)
                .lock()
                .map_err(|_| Error::Unavailable)?;
            let token = request["draft"].as_str().ok_or(Error::Invalid)?;
            let index = drafts
                .iter()
                .position(|(id, _)| id == token)
                .ok_or(Error::Unavailable)?;
            let (token, mut builder) = drafts.remove(index);
            if action == "abort" {
                return Ok(json!({}));
            }
            if action == "finish" {
                return builder.finish();
            }
            builder.append(&request["entry"])?;
            drafts.push((token, builder));
            return Ok(json!({}));
        }
        cache::evaluate(request)
    })();
    match result {
        Ok(payload) => json!({"schema":"guard-cloud-catalog-result.v2","payload":payload}),
        Err(error) => json!({"schema":"guard-cloud-catalog-result.v2","error": match error {
            Error::Invalid=>"catalog_invalid",Error::Limit=>"catalog_limit",Error::Unavailable=>"catalog_unavailable"}}),
    }
}
