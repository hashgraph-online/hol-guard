//! Identity history survives omission from later catalogs. Only immutable
//! artifact facts participate; new origins/qualification can be certified for
//! the same bytes without replacing an installed slot or forgetting history.
use super::*;
use std::collections::BTreeMap;
const MAX_SEEN: usize = 4096;
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Seen {
    sdk: BTreeMap<String, String>,
    platforms: BTreeMap<String, String>,
    python: BTreeMap<String, String>,
}
fn digest(v: &impl Serialize) -> Result<String, String> {
    serde_json::to_vec(v)
        .map(|b| format!("{:x}", Sha256::digest(b)))
        .map_err(|_| error("cigar_catalog_state_invalid"))
}
fn remember(map: &mut BTreeMap<String, String>, id: String, value: String) -> Result<(), String> {
    if map.get(&id).is_some_and(|v| v != &value) {
        return Err(error("cigar_catalog_identity_conflict"));
    }
    map.insert(id, value);
    if map.len() > MAX_SEEN {
        return Err(error("cigar_catalog_identity_limit"));
    }
    Ok(())
}
fn wheel(w: &guard_cigar_release::WheelLock) -> Value {
    json!([
        w.distribution,
        w.version,
        w.filename,
        w.sha256,
        w.bytes,
        w.requires_python
    ])
}
impl Seen {
    pub(super) fn validate(&self) -> Result<(), String> {
        for map in [&self.sdk, &self.platforms, &self.python] {
            if map.len() > MAX_SEEN
                || map.iter().any(|(id, h)| {
                    id.is_empty()
                        || id.len() > 192
                        || !id
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_:-@".contains(&b))
                        || !is_lower_hex(h, 64)
                })
            {
                return Err(error("cigar_catalog_state_invalid"));
            }
        }
        Ok(())
    }
    pub(super) fn remember(&mut self, catalog: &TrustedCatalog) -> Result<(), String> {
        for b in &catalog.document().builds {
            // Withdrawals grant no bytes; retain any earlier immutable identity.
            if b.withdrawn {
                continue;
            }
            remember(
                &mut self.sdk,
                b.identity.build_id.clone(),
                digest(&b.identity)?,
            )?;
            for p in &b.platforms {
                let mut deps: Vec<_> = p.dependencies.iter().collect();
                deps.sort_by(|a, b| a.distribution.cmp(&b.distribution));
                let value = json!([
                    p.platform,
                    p.worker_sha256,
                    p.package_tree_sha256,
                    p.wheel.as_ref().map(wheel),
                    deps.into_iter().map(wheel).collect::<Vec<_>>()
                ]);
                remember(
                    &mut self.platforms,
                    format!("{}@{}", b.identity.build_id, p.platform),
                    digest(&value)?,
                )?;
            }
        }
        for b in &catalog.document().interpreters {
            if b.withdrawn {
                continue;
            }
            let value = json!([
                b.build_id,
                b.python_version,
                b.platform,
                b.source_revision,
                b.archive_sha256,
                b.archive_bytes,
                b.tree_sha256,
                b.files,
                b.expanded_bytes,
                b.executable_sha256
            ]);
            remember(&mut self.python, b.build_id.clone(), digest(&value)?)?;
        }
        self.validate()
    }
}
