//! Control-plane preparation. Capability factories authenticate the publication;
//! native code chooses all objects, dependencies and cache identities.
use guard_policy_snapshot::canonical_json_bytes;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
};
mod cache;
mod metadata;
mod proofs;
mod targets;
#[cfg(test)]
mod tests;
pub(crate) mod transfer;
/// Stable code for a release that does not publish a requested policy. The
/// lifecycle fallback operation authorizes a retry only against this code.
pub(crate) const UNAVAILABLE: &str = "pack_policy_unavailable";
const MAX_SELECTED: usize = 32768;
type Result<T> = std::result::Result<T, Failure>;
enum Failure {
    Batch(Vec<Value>),
    Need(Value),
    Archives(Value),
    Invalid(String),
    Revoked(String, u64),
    Unavailable,
}
impl From<&str> for Failure {
    fn from(s: &str) -> Self {
        Self::Invalid(s.into())
    }
}
fn invalid() -> Failure {
    "pack preparation metadata invalid".into()
}
fn encoded(value: &Value) -> Result<Vec<u8>> {
    canonical_json_bytes(value).map_err(|_| invalid())
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn ids(value: &Value, message: &str) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for id in value.as_array().ok_or_else(|| Failure::from(message))? {
        let id = id
            .as_str()
            .filter(|s| valid_id(s))
            .ok_or_else(|| Failure::from(message))?;
        result.insert(id.to_owned());
        if result.len() > MAX_SELECTED {
            return Err("requested pack selection exceeds admission budget".into());
        }
    }
    Ok(result)
}
fn valid_id(id: &str) -> bool {
    id.len() <= 256
        && id.strip_prefix("command.").is_some_and(|s| {
            !s.is_empty()
                && s.split(['.', '-']).all(|p| {
                    !p.is_empty()
                        && p.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                })
        })
}
struct Preparation<'a> {
    directory: &'a Path,
    root: Value,
    input: &'a Value,
    defaults: BTreeMap<String, Value>,
    details: BTreeMap<String, (Value, Value)>,
    catalog_bytes: usize,
    committed_registry: BTreeSet<String>,
    committed_selected: BTreeSet<String>,
}
impl Preparation<'_> {
    fn metadata(&mut self, id: &str) -> Result<(Value, Value)> {
        if self.input["profile"] == "committed-subset" && !self.committed_registry.contains(id) {
            return Err("offline subset cannot add uncommitted control metadata".into());
        }
        if let Some(value) = self.details.get(id) {
            return Ok(value.clone());
        }
        if self.details.len() >= MAX_SELECTED {
            return Err("pack interface expansion exceeds admission budget".into());
        }
        let record = metadata::lookup(self.directory, &self.root, id, self.defaults.get(id))?
            .ok_or(Failure::Unavailable)?;
        if self.defaults.contains_key(id) && record["trust_class"] == "external" {
            return Err("external policy cannot be selected by defaults".into());
        }
        let catalog = proofs::object(self.directory, &record["catalog_metadata"])?;
        self.catalog_bytes += encoded(&catalog)?.len();
        let list = catalog
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or_else(|| Failure::from("pack metadata exceeds admission budget"))?;
        if self.catalog_bytes > 128 * 1024 * 1024 {
            return Err("pack metadata exceeds admission budget".into());
        }
        let value = &list[0];
        if value["extension_id"] != id
            || ["dependencies", "trust_class", "required", "activation"]
                .iter()
                .any(|f| value[*f] != record[*f])
        {
            return Err("pack availability differs from catalog metadata".into());
        }
        self.details
            .insert(id.into(), (record.clone(), value.clone()));
        Ok((record, value.clone()))
    }
    fn run(&mut self) -> Result<Value> {
        let requested = ids(&self.input["selected"], "requested pack selection invalid")?;
        let mut queued: BTreeSet<String> = self.defaults.keys().cloned().chain(requested).collect();
        if queued.len() > MAX_SELECTED {
            return Err("pack dependency expansion exceeds admission budget".into());
        }
        let mut pending: VecDeque<String> = queued.iter().cloned().collect();
        transfer::prefetch(self, &queued)?;
        let mut selected = BTreeMap::new();
        let mut executables = BTreeSet::new();
        while let Some(id) = pending.pop_front() {
            if self.input["profile"] == "committed-subset" && !self.committed_selected.contains(&id)
            {
                return Err("offline subset cannot activate uncommitted policy".into());
            }
            let (record, catalog) = self.metadata(&id)?;
            metadata::revocation(self.directory, &self.root, &id, &record["manifest"])?;
            // Only selected policy requests payload archives. Related interfaces
            // are metadata and cannot turn an external pack on.
            let manifest =
                proofs::policy_object(self.directory, &record["manifest"], &record["archives"])?;
            let program =
                proofs::policy_object(self.directory, &manifest["program"], &record["archives"])?;
            for reference in program["nodes"].as_object().ok_or_else(invalid)?.values() {
                proofs::policy_object(self.directory, reference, &record["archives"])?;
            }
            proofs::policy_object(
                self.directory,
                &manifest["descriptors"],
                &record["archives"],
            )?;
            let native_catalog =
                proofs::policy_object(self.directory, &manifest["catalog"], &record["archives"])?;
            if native_catalog != json!([catalog])
                || program["catalog_digest"] != hash(&encoded(&native_catalog)?)
            {
                return Err("pack metadata differs from compiled policy".into());
            }
            if let Some(rules) = program["rules"].as_array() {
                for rule in rules {
                    for executable in rule["candidate_executables"]
                        .as_array()
                        .ok_or_else(invalid)?
                    {
                        executables.insert(executable.as_str().ok_or_else(invalid)?.to_owned());
                    }
                }
            }
            selected.insert(id, (manifest, program["catalog_digest"].clone()));
            let mut dependencies = ids(&catalog["dependencies"], "pack dependency invalid")?;
            let permissions = catalog["permissions"].as_array().ok_or_else(invalid)?;
            let owned: BTreeSet<_> = permissions
                .iter()
                .map(|p| p["permission_id"].as_str().ok_or_else(invalid))
                .collect::<Result<_>>()?;
            let mut references = BTreeSet::new();
            for permission in permissions {
                for field in ["dependencies", "implied_permissions"] {
                    for reference in permission[field].as_array().ok_or_else(invalid)? {
                        let reference = reference.as_str().ok_or_else(invalid)?;
                        if !owned.contains(reference) {
                            references.insert(reference.to_owned());
                        }
                    }
                }
            }
            for reference in references {
                let mut owners = Vec::new();
                for candidate in record["related_interfaces"]
                    .as_array()
                    .ok_or_else(invalid)?
                {
                    let candidate = candidate.as_str().ok_or_else(invalid)?;
                    if reference.starts_with(&format!("{candidate}.permission.")) {
                        let (_, interface) = self.metadata(candidate)?;
                        if interface["permissions"]
                            .as_array()
                            .ok_or_else(invalid)?
                            .iter()
                            .any(|p| p["permission_id"] == reference)
                        {
                            owners.push(candidate.to_owned());
                        }
                    }
                }
                if owners.len() != 1 {
                    return Err(
                        "selected permission dependency has no unique authenticated owner".into(),
                    );
                }
                dependencies.insert(owners.remove(0));
            }
            for dependency in dependencies {
                if queued.insert(dependency.clone()) {
                    if queued.len() > MAX_SELECTED {
                        return Err("pack dependency expansion exceeds admission budget".into());
                    }
                    pending.push_back(dependency);
                }
            }
        }
        if selected.is_empty() {
            return Err("pack selection is empty".into());
        }
        let retained = ids(&self.input["retained"], "retained control target invalid")?;
        let mut interfaces: VecDeque<String> =
            self.details.keys().cloned().chain(retained).collect();
        let mut seen = BTreeSet::new();
        let mut transfers = transfer::Transfers::default();
        while let Some(id) = interfaces.pop_front() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if seen.len() > MAX_SELECTED {
                return Err("control metadata expansion exceeds admission budget".into());
            }
            let (record, _) = match self.metadata(&id) {
                Ok(value) => value,
                Err(error) => {
                    transfers.push(error)?;
                    continue;
                }
            };
            for related in ids(
                &record["related_interfaces"],
                "policy interface metadata invalid",
            )? {
                if !seen.contains(&related) {
                    interfaces.push_back(related);
                }
            }
        }
        transfers.finish()?;
        cache::finish(self, &selected, &executables)
    }
}
fn prepare(input: &Value) -> Result<Value> {
    if input["operation"] == "target-metadata" {
        return targets::prepare(input);
    }
    let data = input["release_data"]
        .as_str()
        .filter(|s| s.len() <= 65536)
        .ok_or_else(invalid)?;
    let root: Value = serde_json::from_str(data).map_err(|_| invalid())?;
    let now = input["now"].as_u64().ok_or_else(|| {
        Failure::from("new pack preparation requires fresh authenticated metadata")
    })?;
    if !matches!(
        input["profile"].as_str(),
        Some("remote" | "installed" | "committed-subset")
    ) {
        return Err("pack preparation requires an authenticated publication".into());
    }
    if input["profile"] == "remote"
        && !(root["issued_at"].as_u64().is_some_and(|t| t <= now)
            && root["expires_at"].as_u64().is_some_and(|t| now < t))
    {
        return Err("new pack preparation requires fresh authenticated metadata".into());
    }
    if root["engine"] != input["engine"]
        || input["engine"] != guard_command::source_cli::compiler_info()["implementation_digest"]
    {
        return Err("pack publication requires a different native engine".into());
    }
    ids(&input["selected"], "requested pack selection invalid")?;
    ids(&input["retained"], "retained control target invalid")?;
    if input["validate_only"] == true {
        return Ok(json!({"validated":true}));
    }
    let directory = Path::new(input["directory"].as_str().ok_or_else(invalid)?);
    cache::initialize(directory)?;
    let defaults = &root["policy"]["defaults"];
    let count = defaults["count"]
        .as_u64()
        .filter(|n| *n <= MAX_SELECTED as u64)
        .ok_or_else(|| Failure::from("default pack selection exceeds admission budget"))?;
    let defaults = metadata::entries(directory, &defaults["index"], count)?;
    let mut preparation = Preparation {
        directory,
        root,
        input,
        defaults,
        details: BTreeMap::new(),
        catalog_bytes: 0,
        committed_registry: ids(
            &input["committed_registry"],
            "offline subset registry invalid",
        )?,
        committed_selected: ids(
            &input["committed_selected"],
            "offline subset selection invalid",
        )?,
    };
    preparation.run()
}
fn respond(input: &Value, result: Result<Value>) -> std::result::Result<Value, String> {
    let offline = input["profile"] == "committed-subset";
    let response = match result {
        Ok(value) => value,
        // An offline subset cannot fetch, but the caller can: answering with
        // the typed unavailable reason lets preparation retry against the
        // published root instead of failing the operator's save outright.
        Err(Failure::Batch(_) | Failure::Need(_) | Failure::Archives(_)) if offline => {
            json!({"unavailable": UNAVAILABLE})
        }
        Err(Failure::Batch(needs)) => json!({"needs":needs}),
        Err(Failure::Need(reference)) => json!({"need":reference}),
        Err(Failure::Archives(archives)) => json!({"need_archives":archives}),
        Err(Failure::Revoked(id, epoch)) => json!({"revoked":id,"epoch":epoch}),
        Err(Failure::Unavailable) => json!({"unavailable":UNAVAILABLE}),
        Err(Failure::Invalid(message)) => return Err(message),
    };
    transfer::account(input, response)
}
pub(crate) fn evaluate(input: &Value) -> std::result::Result<Value, String> {
    respond(input, prepare(input))
}
