//! Activation policy only. IO, authenticated capability factories and leases
//! remain at the existing boundary; cache hashes never grant publisher trust.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

mod current;
mod distribution;
mod floor;
mod installed_asset;
pub(crate) mod location;
mod migration;
mod offline;
mod record;
mod release;
mod release_transport;
mod selection;
#[cfg(test)]
mod tests;
mod version;
use floor::{decode, encode, Floor};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub profile: String,
    pub source: String,
    pub engine: String,
    pub root: String,
    pub version: String,
    pub authority: u64,
    pub revocation: u64,
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Identity {
    fn validate(&self) -> Result<(), String> {
        if !matches!(self.profile.as_str(), "installed" | "remote")
            || !hex(&self.source, 40)
            || !hex(&self.engine, 64)
            || !hex(&self.root, 64)
            || self.authority == 0
        {
            return Err("pack_lifecycle_identity_invalid".into());
        }
        version::validate(&self.profile, &self.version)?;
        Ok(())
    }
}

/// The floor an install starts from: the verified installed release and
/// nothing else. Enrollment and a startup that finds no record at all both
/// derive it here, so the two cannot drift apart.
fn enrolled(candidate: Identity, key: &[u8]) -> Result<Value, String> {
    candidate.validate()?;
    if candidate.profile != "installed" {
        return Err("pack_lifecycle_enrollment_requires_release".into());
    }
    Ok(json!({"record": encode(&Floor {
        schema: "guard.command-pack-floor.v1".into(),
        source: candidate.source.clone(),
        authority: candidate.authority,
        revocation: candidate.revocation,
        installed: Some(candidate),
        remote: None,
    }, key)?, "stamp": "guard.command-pack-enrolled.v1"}))
}

fn parse<T: serde::de::DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_value(value.clone()).map_err(|_| "pack_lifecycle_invalid".into())
}

pub(super) fn transition(
    floor: &Floor,
    candidate: &Identity,
    ancestry: &Value,
) -> Result<Floor, String> {
    candidate.validate()?;
    if candidate.authority < floor.authority || candidate.revocation < floor.revocation {
        return Err("pack_lifecycle_epoch_rollback".into());
    }
    let previous = if candidate.profile == "installed" {
        &floor.installed
    } else {
        &floor.remote
    };
    if let Some(previous) = previous {
        let order = version::compare(&candidate.profile, &candidate.version, &previous.version)?;
        if order.is_lt() {
            return Err("pack_lifecycle_version_rollback".into());
        }
        let mut canonical = candidate.clone();
        canonical.version = previous.version.clone();
        if order.is_eq() && canonical != *previous {
            return Err("pack_lifecycle_version_reused".into());
        }
    }
    // Authenticated installed package releases have their own monotonic
    // authority. They do not publish a remote Root or move its ancestry cursor.
    if candidate.profile == "remote"
        && candidate.source != floor.source
        && !(ancestry["status"] == "ahead"
            && ancestry["base_commit"]["sha"] == floor.source
            && ancestry["merge_base_commit"]["sha"] == floor.source
            && ancestry["head_commit"]["sha"] == candidate.source
            && ancestry["behind_by"].as_u64() == Some(0)
            && ancestry["ahead_by"].as_u64().is_some_and(|n| n > 0))
    {
        return Err("pack_lifecycle_source_ancestry_required".into());
    }
    let mut next = floor.clone();
    if candidate.profile == "remote" {
        next.source = candidate.source.clone();
    }
    next.authority = candidate.authority;
    next.revocation = candidate.revocation;
    if candidate.profile == "installed" {
        next.installed = Some(candidate.clone());
    } else {
        next.remote = Some(candidate.clone());
    }
    Ok(next)
}

/// Bounded native-only protocol; unavailable operations fail, never fall back.
pub(super) fn evaluate(input: &Value) -> Result<Value, String> {
    if input["kind"] == "installed-asset" {
        return installed_asset::fetch(input);
    }
    if input["kind"] == "object" {
        return crate::delivery_object::evaluate(input);
    }
    if input["kind"] == "preparation" {
        return crate::pack_preparation::evaluate(input);
    }
    if input["kind"] == "offline" {
        return offline::evaluate(input);
    }
    if input["kind"] == "distribution" {
        return distribution::evaluate(input);
    }
    if input["kind"] == "release-transport" {
        return release_transport::evaluate(input);
    }
    if input["kind"] == "active-security" {
        return crate::active_pack_security::evaluate(input);
    }
    let kind = input["kind"]
        .as_str()
        .ok_or("pack_lifecycle_kind_missing")?;
    if kind == "selection" {
        return selection::select(input);
    }
    if kind == "fallback" {
        // A committed subset reports the same typed unavailability when its
        // cached policy is gone. Re-preparing from the published root is the
        // same authenticated route the installed profile already takes, and it
        // is the only way a saved policy survives an evicted cache.
        return if matches!(
            input["profile"].as_str(),
            Some("installed") | Some("committed-subset")
        ) && input["reason"] == crate::pack_preparation::UNAVAILABLE
        {
            Ok(json!({"profile":"remote"}))
        } else {
            Err("pack_lifecycle_fallback_not_authorized".into())
        };
    }
    if kind == "admission" {
        let profile = input["profile"]
            .as_str()
            .ok_or("pack_lifecycle_profile_invalid")?;
        let now = input["now"]
            .as_f64()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .ok_or("pack_lifecycle_time_invalid")?;
        let (current, lifetime) = match profile {
            "installed" | "committed-subset" => (true, 300.0),
            "remote" => {
                let issued = input["issued_at"]
                    .as_u64()
                    .ok_or("pack_lifecycle_time_invalid")?;
                let expires = input["expires_at"]
                    .as_u64()
                    .ok_or("pack_lifecycle_time_invalid")?;
                let current = issued as f64 <= now && now < expires as f64;
                (
                    current,
                    if current {
                        (expires as f64 - now).min(300.0)
                    } else {
                        0.0
                    },
                )
            }
            _ => return Err("pack_lifecycle_profile_invalid".into()),
        };
        return Ok(json!({"current":current, "lifetime":lifetime}));
    }
    if kind == "installed" {
        return Ok(serde_json::to_value(release::identity(input)?)
            .map_err(|_| "pack_lifecycle_invalid")?);
    }
    let key = input["key"].as_str().ok_or("pack_lifecycle_key_missing")?;
    let key = hex::decode(key).map_err(|_| "pack_lifecycle_key_invalid")?;
    if key.len() != 32 {
        return Err("pack_lifecycle_key_invalid".into());
    }
    if kind == "record" {
        return record::evaluate(input, &key);
    }
    if kind == "migrate" {
        return migration::migrate(input, &key);
    }
    if kind == "legacy-pending" {
        return migration::recover(input, &key);
    }
    if kind == "enroll" {
        // Only the installed capability adapter exposes this under an exclusive
        // lease. Ordinary preparation cannot enroll/recreate protected state.
        return enrolled(release::identity(input)?, &key);
    }
    let encoded = input["floor"]
        .as_str()
        .ok_or("pack_lifecycle_protected_floor_missing")?;
    let floor = decode(encoded, &key)?;
    if kind == "discovery-current" {
        return current::evaluate(input, &floor, &key);
    }
    match kind {
        "read" => Ok(serde_json::to_value(floor).map_err(|_| "pack_lifecycle_invalid")?),
        "plan" => {
            let selected: BTreeSet<String> = parse(&input["selected"])?;
            let retained: BTreeSet<String> = parse(&input["retained"])?;
            let active: Option<BTreeSet<String>> = parse(&input["active"])?;
            let registry: BTreeSet<String> = parse(&input["registry"])?;
            let installed: Option<Identity> = parse(&input["installed"])?;
            let mut admission = floor.clone();
            let mut installed_usable = false;
            if let Some(installed) = installed.as_ref() {
                if floor.installed.as_ref() == Some(installed)
                    && installed.authority >= floor.authority
                    && installed.revocation >= floor.revocation
                {
                    // This floor already admitted exactly this release, so it
                    // stays usable without re-deriving it. Re-deriving it was
                    // the only reason a steady-state preview fell through to
                    // the remote profile, which needs the network for every
                    // saved policy; the floor itself does not move here. A
                    // remote publication that raised the epochs past it sends
                    // it through `transition`, which refuses the rollback.
                    installed_usable = true;
                } else {
                    match transition(&floor, installed, &input["ancestry"]) {
                        Ok(next) => {
                            admission = next;
                            installed_usable = true;
                        }
                        Err(code) if code == "pack_lifecycle_source_ancestry_required" => {
                            if !input["ancestry"].is_null() {
                                return Err(code);
                            }
                            return Ok(json!({"lineage_source":installed.source}));
                        }
                        // A release the floor will not admit is not fatal to
                        // planning: preparation falls back to the published
                        // root, which carries its own authority.
                        Err(code)
                            if matches!(
                                code.as_str(),
                                "pack_lifecycle_epoch_rollback"
                                    | "pack_lifecycle_version_rollback"
                                    | "pack_lifecycle_version_reused"
                            ) => {}
                        Err(code) => return Err(code),
                    }
                }
            }
            let admission_floor = encode(&admission, &key)?;
            let compatible = installed
                .as_ref()
                .is_none_or(|i| input["active_engine"] == i.engine);
            let unchanged =
                serde_json::to_value(&floor).ok() == serde_json::to_value(&admission).ok();
            if unchanged
                && compatible
                && active.is_some_and(|active| {
                    selected.is_subset(&active) && retained.is_subset(&registry)
                })
            {
                return Ok(
                    json!({"profile":"committed-subset", "admission_floor":admission_floor}),
                );
            }
            let profile = if installed_usable {
                "installed"
            } else {
                "remote"
            };
            Ok(json!({"profile":profile, "admission_floor":admission_floor}))
        }
        "transition" => {
            let candidate: Identity = parse(&input["candidate"])?;
            let next = transition(&floor, &candidate, &input["ancestry"])?;
            Ok(json!({"record":encode(&next, &key)?}))
        }
        "subset" => {
            // Retention does not renew timestamps or publisher authority.
            if input["previous"].is_null() || input["previous"] != input["candidate"] {
                return Err("pack_lifecycle_subset_identity_changed".into());
            }
            if input["previous_digest"].is_null()
                || input["previous_digest"] != input["predecessor"]
            {
                return Err("pack_lifecycle_subset_predecessor_changed".into());
            }
            let selected: BTreeSet<String> = parse(&input["selected"])?;
            let active: BTreeSet<String> = parse(&input["active"])?;
            if !selected.is_subset(&active) {
                return Err("pack_lifecycle_subset_expanded".into());
            }
            let value = &input["candidate"];
            let identity = [&floor.installed, &floor.remote]
                .into_iter()
                .flatten()
                .find(|i| {
                    value["source_sha"] == i.source
                        && value["engine"] == i.engine
                        && value["root_digest"] == i.root
                        && value["authority_epoch"] == i.authority
                        && value["revocation_epoch"] == i.revocation
                        && value["publication_id"]
                            == if i.profile == "installed" {
                                "0.0"
                            } else {
                                &i.version
                            }
                })
                .ok_or("pack_lifecycle_subset_below_floor")?;
            transition(&floor, identity, &Value::Null)?;
            Ok(json!({"record":encoded}))
        }
        _ => Err("pack_lifecycle_feature_unavailable".into()),
    }
}

/// The request is held to the stdin frame every runtime subcommand reads. Each
/// operation bounds its own fields, and a signed provenance statement within
/// its bound can grow past a smaller frame once its quotes are escaped.
pub(super) fn run(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > crate::MAX_NATIVE_REQUEST_BYTES {
        return Err("pack_lifecycle_request_too_large".into());
    }
    let input: Value = serde_json::from_slice(bytes).map_err(|_| "pack_lifecycle_invalid")?;
    evaluate(&input)
}
