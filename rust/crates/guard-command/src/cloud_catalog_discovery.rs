//! Fixed discovery CAS format shared with installed metadata preparation.
use super::*;
use crate::native_command_program::source::{read_pack_blob, PackObjectRef};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    schema: String,
    authority: String,
    count: usize,
    first: PackObjectRef,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    schema: String,
    entries: Vec<(String, PackObjectRef)>,
    next: Option<PackObjectRef>,
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if encode(&value)? != bytes {
        return Err(Error::Invalid);
    }
    serde_json::from_value(value).map_err(|_| Error::Invalid)
}
pub fn visit(
    observation: &Observation,
    mut consume: impl FnMut(Value) -> Result<()>,
) -> Result<()> {
    let directory = observation
        .guard_home
        .join("native-runtime/catalog-discovery/objects");
    if guard_secure_fs::contains_symlink_component(&directory) {
        return Err(Error::Invalid);
    }
    let object = |digest: &str| -> std::result::Result<Vec<u8>, &'static str> {
        if !sha(digest) {
            return Err("catalog_digest_invalid");
        }
        guard_secure_fs::read_bounded(&directory.join(format!("{digest}.json")), 65_536)
            .map(|v| v.bytes)
            .map_err(|_| "catalog_object_unavailable")
    };
    let bytes = object(&observation.discovery_root).map_err(|_| Error::Unavailable)?;
    if hash(&bytes) != observation.discovery_root {
        return Err(Error::Invalid);
    }
    let root: Root = decode(&bytes)?;
    if root.schema != "guard.catalog-discovery.v1"
        || root.authority != observation.discovery_authority
        || root.count == 0
        || root.count > 100_000
    {
        return Err(Error::Invalid);
    }
    let mut next = Some(root.first);
    let mut seen = 0;
    let mut pages = 0;
    let mut previous = String::new();
    let mut total = 0;
    while let Some(reference) = next {
        pages += 1;
        if pages > root.count || reference.kind != "data" || reference.expanded_length > 65_536 {
            return Err(Error::Invalid);
        }
        let bytes = read_pack_blob(&reference, &mut |d| object(d)).map_err(|_| Error::Invalid)?;
        total += bytes.len();
        let page: Page = decode(&bytes)?;
        if page.schema != "guard.catalog-discovery-page.v1"
            || page.entries.is_empty()
            || page.entries.len() > 64
        {
            return Err(Error::Invalid);
        }
        for (id, reference) in page.entries {
            seen += 1;
            if id <= previous || seen > root.count {
                return Err(Error::Invalid);
            }
            previous = id.clone();
            // Metadata blobs may use the fixed bounded concat representation.
            let bytes =
                read_pack_blob(&reference, &mut |d| object(d)).map_err(|_| Error::Invalid)?;
            total += bytes.len();
            if total > MAX_TOTAL {
                return Err(Error::Limit);
            }
            let value: Value = decode(&bytes)?;
            if value["extension_id"] != id {
                return Err(Error::Invalid);
            }
            // Validate even overlapped discovery records before active wins.
            consume(projection::project(&value)?)?;
        }
        next = page.next;
    }
    if seen != root.count {
        return Err(Error::Invalid);
    }
    Ok(())
}
