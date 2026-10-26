//! Versioned factory-to-native metadata preparation protocol.
use super::io::OBJECT_BYTES;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub guard_home: PathBuf,
    pub action: Action,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Begin {
        authority: VerifiedAuthority,
    },
    BeginBatched {
        authority: VerifiedAuthority,
    },
    Advance {
        session: String,
        #[serde(deserialize_with = "wire_bytes")]
        data: Vec<u8>,
    },
    AdvanceBatch {
        session: String,
        #[serde(deserialize_with = "wire_batch")]
        data: Vec<Vec<u8>>,
    },
    Resume {
        session: String,
    },
    Validate {
        handle: Handle,
    },
    Abort {
        session: String,
    },
}

// At most 64 existing object-sized responses: <=4 MiB decoded, <5.6 MiB
// base64, within the unchanged 6 MiB resident request bound.
fn wire_batch<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Vec<u8>>, D::Error> {
    struct Batch;
    #[derive(Deserialize)]
    struct Bytes(#[serde(deserialize_with = "wire_bytes")] Vec<u8>);
    impl<'de> serde::de::Visitor<'de> for Batch {
        type Value = Vec<Vec<u8>>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("one to 64 bounded objects")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = Vec::new();
            while let Some(bytes) = seq.next_element::<Bytes>()? {
                if result.len() == 64 {
                    return Err(serde::de::Error::custom("catalog_prepare_batch_budget"));
                }
                result.push(bytes.0);
            }
            if result.is_empty() {
                return Err(serde::de::Error::custom("catalog_prepare_batch_budget"));
            }
            Ok(result)
        }
    }
    deserializer.deserialize_seq(Batch)
}
/// A factory assertion on the authenticated daemon/resident channel, never a
/// public caller-selected path. Signature/release verification stays in the
/// existing fixed factories; native code checks every subsequent byte proof.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedAuthority {
    #[serde(deserialize_with = "wire_bytes")]
    pub data: Vec<u8>,
    pub digest: String,
    pub source_sha: String,
    pub profile: Profile,
    pub expires_at: Option<u64>,
}

fn wire_bytes<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error> {
    let encoded = String::deserialize(deserializer)?;
    if encoded.len() > OBJECT_BYTES.div_ceil(3) * 4 {
        return Err(serde::de::Error::custom("catalog_prepare_object_budget"));
    }
    let bytes = STANDARD.decode(encoded).map_err(serde::de::Error::custom)?;
    if bytes.is_empty() || bytes.len() > OBJECT_BYTES {
        return Err(serde::de::Error::custom("catalog_prepare_object_budget"));
    }
    Ok(bytes)
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Installed,
    Remote,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Handle {
    pub root: String,
    pub authority: String,
    pub token: String,
    pub profile: Profile,
    pub expires_at: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest {
    pub guard_home: PathBuf,
    pub handle: Handle,
    pub read: crate::catalog_read_model::CatalogReadRequestV1,
}
