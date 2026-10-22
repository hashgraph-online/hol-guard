//! The one structural check for where a published asset lives. Preparation,
//! distribution-root validation and the delivery fetch share it, so a location
//! accepted by one is accepted by all of them.
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    Location,
    Identity,
    Container,
}

impl Rejection {
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::Location => "delivery asset location invalid",
            Self::Identity => "delivery asset identity invalid",
            Self::Container => "delivery container location invalid",
        }
    }
}

fn tag() -> &'static Regex {
    static TAG: OnceLock<Regex> = OnceLock::new();
    TAG.get_or_init(|| {
        Regex::new(r"^extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}$").unwrap()
    })
}

fn container() -> &'static Regex {
    static CONTAINER: OnceLock<Regex> = OnceLock::new();
    CONTAINER.get_or_init(|| Regex::new(r"^(objects|packs)-[0-9]{6}\.zip$").unwrap())
}

/// A location is exactly `{tag, asset}` for a standalone asset, or
/// `{tag, asset, member}` for a member of a bounded container.
pub(crate) fn check(value: &Value, sha: &str, kind: &str) -> Result<(), Rejection> {
    let valid_digest = sha.len() == 64
        && sha
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    let Some(map) = value.as_object() else {
        return Err(Rejection::Location);
    };
    let shape = map.contains_key("tag")
        && map.contains_key("asset")
        && (map.len() == 2 || (map.len() == 3 && map.contains_key("member")));
    let tag_ok = value["tag"].as_str().is_some_and(|t| tag().is_match(t));
    if !matches!(kind, "object" | "pack") || !valid_digest || !shape || !tag_ok {
        return Err(Rejection::Location);
    }
    let (prefix, suffix) = if kind == "object" {
        ("objects-", "json")
    } else {
        ("packs-", "zip")
    };
    let expected = format!("{kind}-{sha}.{suffix}");
    if map.len() == 2 {
        return if value["asset"] == expected {
            Ok(())
        } else {
            Err(Rejection::Identity)
        };
    }
    let member_ok = value["member"] == expected;
    let asset_ok = value["asset"]
        .as_str()
        .is_some_and(|a| container().is_match(a) && a.starts_with(prefix));
    if member_ok && asset_ok {
        Ok(())
    } else {
        Err(Rejection::Container)
    }
}

#[cfg(test)]
#[path = "location_tests.rs"]
mod tests;
