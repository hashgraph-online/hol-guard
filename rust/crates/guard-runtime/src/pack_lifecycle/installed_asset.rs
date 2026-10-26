//! Positive immutable data only. An installed 0.0 Root never becomes an update
//! publisher or acquires an invented expiry. Policy admission verifies the
//! selected root-to-record proof and archive digest separately.
use super::*;

pub(super) fn fetch(input: &Value) -> Result<Value, String> {
    let identity = release::identity(input)?;
    destination(&identity.source, &input["location"], &input["length"])
}

fn destination(source: &str, location: &Value, length: &Value) -> Result<Value, String> {
    let invalid = || "pack_installed_asset_invalid".to_string();
    let fields = location.as_object().ok_or_else(invalid)?;
    if fields.len() != 2 || !fields.contains_key("tag") || !fields.contains_key("asset") {
        return Err(invalid());
    }
    let tag = location["tag"].as_str().ok_or_else(invalid)?;
    let prefix = format!("extension-data-{source}-0.0-");
    let batch = tag.strip_prefix(&prefix).ok_or_else(invalid)?;
    let asset = location["asset"].as_str().ok_or_else(invalid)?;
    let (digest, bound) = if let Some(value) = asset
        .strip_prefix("pack-")
        .and_then(|s| s.strip_suffix(".zip"))
    {
        (value, 32 * 1024 * 1024)
    } else {
        return Err(invalid());
    };
    if !hex(source, 40)
        || batch.len() != 6
        || !batch.bytes().all(|b| b.is_ascii_digit())
        || !hex(digest, 64)
        || !length.as_u64().is_some_and(|n| n > 0 && n <= bound)
    {
        return Err(invalid());
    }
    Ok(json!({
        "url": format!("https://github.com/hashgraph-online/hol-guard/releases/download/{tag}/{asset}"),
        "sha256": digest,
        "length": length,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_public_positive_asset_only() {
        let source = "a".repeat(40);
        let target = json!({"tag":format!("extension-data-{source}-0.0-000000"),
            "asset":format!("pack-{}.zip", "b".repeat(64))});
        let result = destination(&source, &target, &json!(10)).unwrap();
        assert!(result["url"]
            .as_str()
            .unwrap()
            .starts_with("https://github.com/hashgraph-online/hol-guard/releases/download/"));
        for length in [json!(0), json!(-1), json!(33554433u64), json!("10")] {
            assert!(destination(&source, &target, &length).is_err());
        }
        for field in ["url", "member"] {
            let mut substituted = target.clone();
            substituted[field] = json!("https://example.com/policy");
            assert!(destination(&source, &substituted, &json!(10)).is_err());
        }
        for tag in [
            format!("extension-data-{}-0.0-000000", "c".repeat(40)),
            format!("extension-data-{source}-1.0-000000"),
            format!("extension-data-{source}-0.0-../000"),
        ] {
            let mut substituted = target.clone();
            substituted["tag"] = json!(tag);
            assert!(destination(&source, &substituted, &json!(10)).is_err());
        }
        let mut metadata = target;
        metadata["asset"] = json!(format!("object-{}.json", "b".repeat(64)));
        assert!(destination(&source, &metadata, &json!(10)).is_err());
    }
}
