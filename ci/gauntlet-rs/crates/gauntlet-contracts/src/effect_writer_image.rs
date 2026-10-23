//! Bounded, post-event process samples. These describe the image seen while
//! a close-write pidfd was held; they do not identify the image at write time
//! or establish that a Guard request caused the write.

use crate::EffectFileHandle;
use serde_json::Value;
use std::collections::BTreeSet;

pub const MAX_EFFECT_WRITER_IMAGES: usize = 64;
pub const EFFECT_IMAGE_JOURNAL_SCHEMA: &str = "hol-gauntlet-staging-effect-events.v3";
pub const EFFECT_IMAGE_RECEIPT_SCHEMA: &str = "hol-gauntlet-staging-effect-events-receipt.v3";

fn exact(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn positive(value: &Value, maximum: u64) -> bool {
    value.as_u64().is_some_and(|n| n > 0 && n <= maximum)
}

fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn valid_sample(sample: &Value) -> bool {
    exact(
        sample,
        &[
            "executable_sha256",
            "argv_sha256",
            "observed_action",
            "uid",
            "gid",
            "namespace_pid",
            "parent_pid",
            "no_new_privileges",
            "seccomp_mode",
            "namespaces",
        ],
    ) && digest(&sample["executable_sha256"])
        && digest(&sample["argv_sha256"])
        && matches!(
            sample["observed_action"].as_str(),
            Some(
                "serve-managed"
                    | "supervise-managed"
                    | "resident-client-stream"
                    | "resident-client"
                    | "other"
            )
        )
        && sample["uid"].as_u64() == Some(10004)
        && sample["gid"].as_u64() == Some(10004)
        && positive(&sample["namespace_pid"], i32::MAX as u64)
        && positive(&sample["parent_pid"], i32::MAX as u64)
        && sample["no_new_privileges"] == true
        && sample["seccomp_mode"].as_u64() == Some(2)
        && exact(&sample["namespaces"], &["mnt", "pid", "user"])
        && ["mnt", "pid", "user"].iter().all(|name| {
            let namespace = &sample["namespaces"][name];
            exact(namespace, &["device", "inode"])
                && positive(&namespace["device"], u64::MAX)
                && positive(&namespace["inode"], u64::MAX)
        })
}

/// Validate an optional journal extension against already-validated v3 event
/// rows. Empty or unavailable samples are valid custody, never positive proof.
pub fn validate_effect_writer_images(images: &Value, events: &[Value]) -> bool {
    let Some(images) = images
        .as_array()
        .filter(|rows| rows.len() <= MAX_EFFECT_WRITER_IMAGES)
    else {
        return false;
    };
    let mut seen = BTreeSet::new();
    images.iter().all(|image| {
        if !exact(
            image,
            &[
                "event_sequence",
                "surface",
                "writer_pid",
                "writer_start_ticks",
                "sample",
                "unavailable_reason",
            ],
        ) || !matches!(
            image["surface"].as_str(),
            Some("provider-remote" | "provider-home" | "contained-output")
        ) {
            return false;
        }
        let Some(index) = image["event_sequence"]
            .as_u64()
            .and_then(|n| n.checked_sub(1))
            .and_then(|n| usize::try_from(n).ok())
        else {
            return false;
        };
        let Some(event) = events.get(index) else {
            return false;
        };
        if !seen.insert(index)
            || event["sequence"].as_u64() != Some(index as u64 + 1)
            || EffectFileHandle::from_json(&event["file_handle"]).is_none()
            || !positive(&image["writer_pid"], i32::MAX as u64)
            || image["writer_pid"] != event["reported_pid"]
            || image["writer_start_ticks"] != event["writer"]["start_ticks"]
        {
            return false;
        }
        if image["sample"].is_null() {
            match image["unavailable_reason"].as_str() {
                Some("pidfd-unavailable") => {
                    event["pidfd_available"] == false && event["writer"].is_null()
                }
                Some("writer-unavailable") => {
                    event["pidfd_available"] == true && event["writer"].is_null()
                }
                Some("outside-product-service" | "process-sample-unavailable") => {
                    event["pidfd_available"] == true
                        && positive(&image["writer_start_ticks"], u64::MAX)
                }
                _ => false,
            }
        } else {
            image["unavailable_reason"].is_null()
                && event["pidfd_available"] == true
                && event["owner"].as_u64() == Some(10004)
                && event["writer"]["pid"] == image["writer_pid"]
                && positive(&image["writer_start_ticks"], u64::MAX)
                && valid_sample(&image["sample"])
        }
    })
}

#[cfg(test)]
#[path = "effect_writer_image_tests.rs"]
mod tests;
