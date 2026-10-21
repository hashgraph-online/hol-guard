//! Authenticated security observations, independent of SQLite and activation floors.
//! The transport invokes this only with fixed verified publication capabilities.
use guard_policy_snapshot::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) mod proofs;
mod trust;
const DOMAIN: &[u8] = b"hol-guard.active-pack-security.v1\0";
pub(crate) const FILE: &str = "active-pack-security.v1.json";
const MAX_RECORD: usize = 262144;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Security {
    schema: String,
    authority: u64,
    epoch: u64,
    root: Value,
    publication: String,
    security_root: String,
    lineage_floor: String,
    identity: Value,
    active: String,
    program: String,
    pending: bool,
    // Keys are authenticated revocation lookup identities; absence never restores.
    facts: BTreeMap<String, Value>,
    applied: BTreeMap<String, Value>,
    pub(crate) quarantine: BTreeSet<String>,
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    canonical_json_bytes(value).map_err(|_| "active_security_invalid".into())
}
fn digest(value: &Value) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(canonical(value)?)))
}
fn mac(key: &[u8], domain: &[u8], bytes: &[u8]) -> String {
    let mut framed = domain.to_vec();
    framed.extend_from_slice(bytes);
    hex::encode(
        ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), &framed).as_ref(),
    )
}
fn verify(key: &[u8], domain: &[u8], bytes: &[u8], tag: &str) -> Result<(), String> {
    let mut framed = domain.to_vec();
    framed.extend_from_slice(bytes);
    let tag = hex::decode(tag).map_err(|_| "active_security_authentication_failed")?;
    ring::hmac::verify(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key),
        &framed,
        &tag,
    )
    .map_err(|_| "active_security_authentication_failed".into())
}

impl Security {
    pub(crate) fn lineage_floor(&self) -> &str {
        &self.lineage_floor
    }
    pub(crate) fn check_discovery(&self, root: &Value) -> Result<(), String> {
        let authority = root["authority_epoch"]
            .as_u64()
            .ok_or("active_security_epoch_invalid")?;
        let epoch = root["policy"]["revocations"]["epoch"]
            .as_u64()
            .ok_or("active_security_epoch_invalid")?;
        if authority < self.authority || epoch < self.epoch {
            return Err("active_security_epoch_rollback".into());
        }
        if epoch == self.epoch
            && root["policy"]["revocations"] != self.root["policy"]["revocations"]
        {
            return Err("active_security_epoch_reused".into());
        }
        Ok(())
    }
    pub(crate) fn decode(encoded: &str, key: &[u8]) -> Result<Self, String> {
        if encoded.len() > MAX_RECORD {
            return Err("active_security_bounds".into());
        }
        let value: Value = serde_json::from_str(encoded).map_err(|_| "active_security_invalid")?;
        let body = canonical(&value["body"])?;
        verify(
            key,
            DOMAIN,
            &body,
            value["mac"].as_str().ok_or("active_security_invalid")?,
        )?;
        let state: Self = serde_json::from_slice(&body).map_err(|_| "active_security_invalid")?;
        if state.schema != "guard.active-pack-security.v1"
            || state.authority == 0
            || state.facts.len() > 1024
            || state.quarantine.len() > 32768
        {
            return Err("active_security_invalid".into());
        }
        Ok(state)
    }
    fn encode(&self, key: &[u8]) -> Result<String, String> {
        let body = serde_json::to_value(self).map_err(|_| "active_security_invalid")?;
        let value = json!({"mac":mac(key, DOMAIN, &canonical(&body)?), "body":body});
        let bytes = canonical(&value)?;
        if bytes.len() > MAX_RECORD {
            return Err("active_security_bounds".into());
        }
        String::from_utf8(bytes).map_err(|_| "active_security_invalid".into())
    }
    pub(crate) fn applicable_digest(&self) -> Result<Option<String>, String> {
        // Complete proofs of unchanged active policy do not churn approval identity.
        if !self.pending && self.quarantine.is_empty() && self.applied.is_empty() {
            return Ok(None);
        }
        let mut value =
            json!({"pending":self.pending,"quarantine":self.quarantine,"facts":self.applied});
        if self.pending {
            value["required_epoch"] = json!([self.authority, self.epoch, self.security_root]);
        }
        digest(&value).map(Some)
    }
    fn answer(&self, key: &[u8]) -> Result<Value, String> {
        Ok(
            json!({"record":self.encode(key)?, "applicable_digest":self.applicable_digest()?,
            "pending":self.pending,"quarantine":self.quarantine}),
        )
    }
    pub(crate) fn pending(&self) -> bool {
        self.pending
    }
    pub(crate) fn program(&self) -> &str {
        &self.program
    }
}

pub(crate) fn active(input: &Value, key: &[u8]) -> Result<Value, String> {
    let bytes = input["activation"]
        .as_str()
        .ok_or("active_security_activation_missing")?
        .as_bytes();
    if bytes.len() > 65536 || hex::encode(Sha256::digest(bytes)) != input["activation_digest"] {
        return Err("active_security_activation_invalid".into());
    }
    let purpose = b"command-pack-activation.v1";
    let purpose_key = hex::decode(mac(
        key,
        b"hol-guard.extension-control-authority.v1\0",
        purpose,
    ))
    .map_err(|_| "active_security_invalid")?;
    verify(
        &purpose_key,
        b"",
        bytes,
        input["activation_mac"]
            .as_str()
            .ok_or("active_security_activation_invalid")?,
    )?;
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "active_security_activation_invalid")?;
    if value["purpose"] != "command-pack-activation.v1"
        || value["authority_schema_version"] != 1
        || !matches!(
            value["schema"].as_str(),
            Some("guard.command-pack-activation.v1" | "guard.command-pack-activation.v2")
        )
    {
        return Err("active_security_activation_invalid".into());
    }
    Ok(value)
}

// The Python daemon reuses answers to the operations handled before `active`
// below (scope, check, read, change, marker, binding and resume) for identical
// requests. They must stay pure functions of the request: no files, clock or
// randomness. An operation that needs any of those belongs after `active`, and
// must not be added to `_PURE` in catalog_delivery/active_security.py.
pub(crate) fn evaluate(input: &Value) -> Result<Value, String> {
    let key = hex::decode(input["key"].as_str().ok_or("active_security_key_missing")?)
        .map_err(|_| "active_security_key_invalid")?;
    if key.len() != 32 {
        return Err("active_security_key_invalid".into());
    }
    let old = input["record"]
        .as_str()
        .map(|s| Security::decode(s, &key))
        .transpose()?;
    let operation = input["operation"]
        .as_str()
        .ok_or("active_security_operation_invalid")?;
    if operation == "scope" || operation == "check" {
        let applicable = old
            .as_ref()
            .map(Security::applicable_digest)
            .transpose()?
            .flatten();
        if operation == "check" && json!(applicable) != input["expected"] {
            return Err("active_security_prepared_scope_conflict".into());
        }
        return Ok(json!({"applicable_digest":applicable}));
    }
    if operation == "read" {
        return old.ok_or("active_security_record_missing")?.answer(&key);
    }
    if operation == "change" {
        let next = Security::decode(
            input["next"]
                .as_str()
                .ok_or("active_security_record_missing")?,
            &key,
        )?;
        return Ok(
            json!({"enforcement_changed":old.as_ref().map(Security::applicable_digest).transpose()?.flatten() != next.applicable_digest()?
            || old.as_ref().is_some_and(|old| old.program != next.program)}),
        );
    }
    if operation == "marker" {
        let mut marker = input["marker"].clone();
        let applicable = old
            .as_ref()
            .map(Security::applicable_digest)
            .transpose()?
            .flatten();
        if let Some(applicable) = applicable {
            // A retained v1 closed marker predates pack projection. Bind its
            // upgrade to the program in the authenticated security observation.
            if marker.get("pack_program_digest").is_none() {
                marker["pack_program_digest"] = old.as_ref().unwrap().program.clone().into();
            }
            marker["schema"] = "guard.native-command-control-authority.v3".into();
            marker["active_security_digest"] = applicable.into();
        } else if marker.get("active_security_digest").is_some() {
            if marker.get("pack_program_digest").is_some() {
                marker["schema"] = "guard.native-command-control-authority.v2".into();
            }
            marker
                .as_object_mut()
                .ok_or("active_security_marker_invalid")?
                .remove("active_security_digest");
        }
        return Ok(marker);
    }
    if operation == "binding" {
        let mut binding: guard_contracts::NativeCommandControlBindingV1 =
            serde_json::from_value(input["binding"].clone())
                .map_err(|_| "active_security_binding_invalid")?;
        binding.active_security_digest = old
            .as_ref()
            .map(Security::applicable_digest)
            .transpose()?
            .flatten();
        binding.effective_digest = binding.compute_effective_digest().map_err(str::to_owned)?;
        return serde_json::to_value(binding).map_err(|_| "active_security_binding_invalid".into());
    }
    let header = active(input, &key)?;
    if operation == "resume" {
        let state = old.ok_or("active_security_record_missing")?;
        return Ok(
            json!({"active_matches":state.active == input["activation_digest"],
            "publication":state.publication}),
        );
    }
    let active_digest = input["activation_digest"]
        .as_str()
        .ok_or("active_security_activation_invalid")?;
    if operation == "begin" {
        let publication = input["publication"]
            .as_str()
            .ok_or("active_security_root_missing")?;
        let root_digest = hex::encode(Sha256::digest(publication.as_bytes()));
        let root: Value =
            serde_json::from_str(publication).map_err(|_| "active_security_root_invalid")?;
        let epoch = root["policy"]["revocations"]["epoch"]
            .as_u64()
            .ok_or("active_security_epoch_invalid")?;
        let authority = root["authority_epoch"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("active_security_epoch_invalid")?;
        let security_root = digest(&json!({"revocations":root["policy"]["revocations"],
            "authority":authority,"engine":root["engine"]}))?;
        if let Some(old) = &old {
            if epoch < old.epoch || authority < old.authority {
                if input["profile"] == "installed" {
                    return Ok(json!({"ignored":true}));
                }
                return Err("active_security_epoch_rollback".into());
            }
            if input["profile"] == "installed"
                && old.identity["profile"] == "remote"
                && epoch == old.epoch
                && authority == old.authority
            {
                return Ok(json!({"ignored":true}));
            }
            if epoch == old.epoch
                && root["policy"]["revocations"] != old.root["policy"]["revocations"]
            {
                return Err("active_security_epoch_reused".into());
            }
            if root == old.root
                && root_digest == old.identity["root"]
                && active_digest == old.active
                && !old.pending
            {
                return old.answer(&key);
            }
        }
        // Reuse the lifecycle owner's native source/version transition. This
        // record advances a separate observation floor, never the activation
        // floor, so even a publication with unavailable proofs cannot roll back
        // the latest authenticated observation on a later outage.
        let identity = if input["profile"].is_null() {
            old.as_ref()
                .filter(|old| old.root == root)
                .map(|old| old.identity.clone())
                .ok_or("active_security_retained_root_mismatch")?
        } else if input["profile"] == "installed" {
            let identity = input["installed_identity"].clone();
            if identity["root"] != root_digest
                || identity["source"] != root["source_sha"]
                || identity["engine"] != root["engine"]
                || identity["authority"] != authority
                || identity["revocation"] != epoch
                || identity["profile"] != "installed"
            {
                return Err("active_security_installed_identity_mismatch".into());
            }
            identity
        } else if input["profile"] == "remote" {
            json!({"profile":"remote","source":root["source_sha"],"engine":root["engine"],
                "root":root_digest,"version":root["publication_id"],"authority":authority,"revocation":epoch})
        } else {
            return Err("active_security_profile_invalid".into());
        };
        let lineage_floor = old
            .as_ref()
            .map(|old| old.lineage_floor.as_str())
            .or_else(|| input["lineage_floor"].as_str())
            .ok_or("active_security_lineage_floor_missing")?;
        let transition =
            crate::pack_lifecycle::evaluate(&json!({"kind":"transition","key":input["key"],
            "floor":lineage_floor,"candidate":identity,"ancestry":input["ancestry"]}));
        let lineage = match transition {
            Ok(value) => value["record"]
                .as_str()
                .ok_or("active_security_lineage_invalid")?
                .to_owned(),
            Err(code)
                if code == "pack_lifecycle_source_ancestry_required"
                    && input["ancestry"].is_null() =>
            {
                return Ok(
                    json!({"lineage_floor":lineage_floor,"lineage_source":root["source_sha"]}),
                );
            }
            Err(code) => return Err(code),
        };
        let mut state = old.unwrap_or(Security {
            schema: "guard.active-pack-security.v1".into(),
            authority,
            epoch,
            root: Value::Null,
            publication: String::new(),
            security_root: String::new(),
            active: String::new(),
            program: String::new(),
            pending: true,
            lineage_floor: String::new(),
            identity: Value::Null,
            facts: BTreeMap::new(),
            applied: BTreeMap::new(),
            quarantine: BTreeSet::new(),
        });
        state.lineage_floor = lineage;
        state.identity = identity;
        state.authority = authority;
        state.epoch = epoch;
        state.root = root;
        state.publication = publication.into();
        state.security_root = security_root;
        state.active = active_digest.into();
        state.program = header["program_digest"]
            .as_str()
            .ok_or("active_security_activation_invalid")?
            .into();
        state.pending = true;
        // Pending is a global terminal quarantine. Retain every known fact,
        // without duplicating its old applicable projection in the bounded
        // protected record while a newer proof set is incomplete.
        state.applied.clear();
        state.quarantine.clear();
        return state.answer(&key);
    }
    let mut state = old.ok_or("active_security_record_missing")?;
    if state.active != active_digest {
        return Err("active_security_activation_conflict".into());
    }
    if operation != "complete" {
        return Err("active_security_operation_invalid".into());
    }
    let directory = std::path::Path::new(
        input["directory"]
            .as_str()
            .ok_or("active_security_directory_missing")?,
    );
    let request = match proofs::complete(&mut state, &header, directory) {
        Ok(()) => return state.answer(&key),
        Err(proofs::Failure::Need(reference)) => json!({"need":reference}),
        Err(proofs::Failure::Archives(archives)) => json!({"need_archives":archives}),
        Err(proofs::Failure::Invalid(code)) => return Err(code.into()),
    };
    crate::pack_preparation::transfer::account(input, request)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
pub(crate) use tests::fixture as fixture_record;
