//! Byte integrity of catalog delivery objects and transfer containers.
//!
//! The delivery channel fetches small content-addressed objects, either whole
//! or as members of bounded containers. Python moves bytes and holds file
//! handles; every decision about whether those bytes are the objects they claim
//! to be is made here, so there is one implementation of each check.
//!
//! Operations, selected by `operation`:
//! - `asset`: resolve and validate the release asset a location names.
//! - `member`: read one member out of a container file, verified by digest.
//! - `installed`: resolve a location of the installed bundle and read its member.
//! - `expand`: expand an object into its blob from a cache directory.
//! - `verify`: check fetched object bytes against the length and digest asked.
//!
//! A rejected input is a normal reply, `{"rejected": <message>}`, so the caller
//! can keep its own error contract. Only an unknown operation is a hard error.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod container;
mod expand;
mod files;
mod installed;
mod location;
pub(crate) mod stored_zip;

type Outcome = Result<Value, String>;

fn request() -> String {
    "delivery object request invalid".into()
}

/// Fetched bytes must have the length and digest of the object that was asked
/// for before they are written anywhere.
fn verify(input: &Value) -> Outcome {
    let data = input["data"]
        .as_str()
        .and_then(|text| STANDARD.decode(text).ok())
        .ok_or_else(request)?;
    let digest = input["sha256"].as_str().ok_or_else(request)?;
    let length = input["length"].as_u64().ok_or_else(request)?;
    if u64::try_from(data.len()).ok() != Some(length)
        || hex::encode(Sha256::digest(&data)) != digest
    {
        return Err("fetched delivery object integrity invalid".into());
    }
    Ok(json!({"verified": true}))
}

pub(crate) fn evaluate(input: &Value) -> Result<Value, String> {
    let outcome = match input["operation"].as_str() {
        Some("asset") => location::asset(input),
        Some("member") => container::member(input),
        Some("installed") => installed::fetch(input),
        Some("installed-batch") => installed::batch(input),
        Some("expand") => expand::run(input),
        Some("verify") => verify(input),
        _ => return Err(request()),
    };
    Ok(outcome.unwrap_or_else(|message| json!({"rejected": message})))
}

#[cfg(test)]
#[path = "delivery_object_tests.rs"]
mod tests;
