//! Codex: the legacy-adoption bindings `codex_detect` reports, selected over
//! the payloads it parsed itself, so the inventory and the ownership it
//! claims come from the same bytes.
//!
//! The request is the `codex_hook_owners` `legacy` op without `hooks`:
//! `expected`, `argv`, `legacy_argv`, `statuses`, `windows` and
//! `long_paths`. A value JSON cannot carry (a TOML date, a non-finite float)
//! is a token while handlers are compared, as `_Wire` sends it, and a binding
//! holding one is left out (`wire_codex_hook_bindings`), so the hook it would
//! have claimed stays reviewable as unmanaged.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use super::codex::{compact, flag};
use super::codex_owners::{long_paths, Legacy};
use crate::codex_value::HookVal;
use crate::cursor_hook_command::Syntax;
use crate::pyjson::PyVal;

const FIELDS: [&str; 6] = [
    "expected",
    "argv",
    "legacy_argv",
    "statuses",
    "windows",
    "long_paths",
];

pub(crate) struct DetectLegacy {
    legacy: Legacy,
    syntax: Syntax,
    known: BTreeSet<String>,
}

impl DetectLegacy {
    /// `None` when the request is malformed.
    pub(crate) fn parse(fields: &Map<String, Value>) -> Option<Self> {
        if fields.len() != FIELDS.len() || FIELDS.iter().any(|key| !fields.contains_key(*key)) {
            return None;
        }
        let long_paths = long_paths(fields).ok()?;
        let known = long_paths.keys().cloned().collect();
        Some(Self {
            legacy: Legacy::parse(fields).ok()?,
            syntax: Syntax::new(flag(fields, "windows").ok()?, long_paths),
            known,
        })
    }

    /// `_legacy_wire_bindings` over one parsed source.
    pub(crate) fn bindings(&mut self, payload: &HookVal) -> Vec<Value> {
        let Some(hooks @ HookVal::Dict(_)) = payload.get("hooks") else {
            return Vec::new();
        };
        let mut tokens = Tokens::new(hooks);
        let PyVal::Dict(entries) = tokens.py(hooks) else {
            return Vec::new();
        };
        self.legacy
            .bindings(&entries, &mut self.syntax)
            .iter()
            .filter(|binding| !tokens.holds(binding))
            .filter_map(|binding| serde_json::from_str(&compact(binding, false)).ok())
            .collect()
    }

    /// The 8.3 short names the host must expand before the answer holds.
    pub(crate) fn unresolved(&self) -> Vec<String> {
        self.syntax
            .short_tokens()
            .iter()
            .filter(|token| !self.known.contains(*token))
            .cloned()
            .collect()
    }
}

/// Stand-ins for the scalars JSON cannot carry. The prefix starts with NUL
/// and grows until no string in the payload starts with it, so a token only
/// ever means what this issued; equal meanings share one.
struct Tokens {
    prefix: String,
    issued: BTreeMap<(&'static str, String), String>,
}

impl Tokens {
    fn new(value: &HookVal) -> Self {
        let mut present = Vec::new();
        strings(value, &mut present);
        let mut prefix = "\0hol-guard-token".to_owned();
        while present.iter().any(|text| text.starts_with(&prefix)) {
            prefix.push('\0');
        }
        Self {
            prefix,
            issued: BTreeMap::new(),
        }
    }

    fn token(&mut self, kind: &'static str, meaning: String) -> PyVal {
        let next = format!("{}-{}", self.prefix, self.issued.len());
        PyVal::Str(self.issued.entry((kind, meaning)).or_insert(next).clone())
    }

    fn py(&mut self, value: &HookVal) -> PyVal {
        match value {
            HookVal::Null => PyVal::Null,
            HookVal::Bool(flag) => PyVal::Bool(*flag),
            HookVal::Int(digits) => PyVal::Int(digits.clone()),
            HookVal::Float(number) if number.is_finite() => PyVal::Float(*number),
            HookVal::Float(number) => self.token("float", number.to_string()),
            HookVal::Str(text) => PyVal::Str(text.clone()),
            HookVal::List(items) => PyVal::List(items.iter().map(|item| self.py(item)).collect()),
            HookVal::Dict(entries) => PyVal::Dict(
                entries
                    .iter()
                    .map(|(key, item)| (key.clone(), self.py(item)))
                    .collect(),
            ),
            HookVal::Temporal(kind, iso) => self.token(kind, iso.clone()),
        }
    }

    fn holds(&self, value: &PyVal) -> bool {
        match value {
            PyVal::Str(text) => text.starts_with(&self.prefix),
            PyVal::List(items) => items.iter().any(|item| self.holds(item)),
            PyVal::Dict(entries) => entries.iter().any(|(_, item)| self.holds(item)),
            _ => false,
        }
    }
}

fn strings<'a>(value: &'a HookVal, out: &mut Vec<&'a str>) {
    match value {
        HookVal::Str(text) => out.push(text),
        HookVal::List(items) => items.iter().for_each(|item| strings(item, out)),
        HookVal::Dict(entries) => entries.iter().for_each(|(key, item)| {
            out.push(key);
            strings(item, out);
        }),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const HOOK: &str = "/opt/guard/bin/python -I /opt/guard/bridge.py";

    fn legacy(windows: bool) -> DetectLegacy {
        let expected = json!([{"event": "PreToolUse", "group": {"matcher": "*"}}]).to_string();
        let Value::Object(fields) = json!({
            "expected": expected,
            "argv": ["/opt/guard/bin/python", "-I", "/opt/guard/bridge.py"],
            "legacy_argv": ["/usr/bin/python3", "-I", "/opt/guard/bridge.py"],
            "statuses": ["HOL Guard reviewing"],
            "windows": windows,
            "long_paths": {},
        }) else {
            unreachable!()
        };
        DetectLegacy::parse(&fields).expect("valid request")
    }

    fn group(extra: (&str, HookVal)) -> HookVal {
        let handler = HookVal::Dict(vec![
            ("type".into(), HookVal::Str("command".into())),
            ("command".into(), HookVal::Str(HOOK.into())),
            (
                "statusMessage".into(),
                HookVal::Str("HOL Guard reviewing".into()),
            ),
        ]);
        HookVal::Dict(vec![(
            "hooks".into(),
            HookVal::Dict(vec![(
                "PreToolUse".into(),
                HookVal::List(vec![HookVal::Dict(vec![
                    ("matcher".into(), HookVal::Str("*".into())),
                    ("hooks".into(), HookVal::List(vec![handler])),
                    (extra.0.into(), extra.1),
                ])]),
            )]),
        )])
    }

    #[test]
    fn a_current_package_handler_is_claimed() {
        let bindings = legacy(false).bindings(&group(("note", HookVal::Str("x".into()))));
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0]["event"], "PreToolUse");
        assert_eq!(bindings[0]["handler"]["command"], HOOK);
    }

    #[test]
    fn a_binding_json_cannot_carry_is_left_out() {
        let stamp = HookVal::Temporal("date", "2020-01-01".into());
        assert!(legacy(false).bindings(&group(("when", stamp))).is_empty());
        let nan = HookVal::Float(f64::NAN);
        assert!(legacy(false).bindings(&group(("ratio", nan))).is_empty());
    }

    #[test]
    fn payloads_without_hooks_claim_nothing() {
        let mut legacy = legacy(false);
        assert!(legacy.bindings(&HookVal::Dict(Vec::new())).is_empty());
        let listed = HookVal::Dict(vec![("hooks".into(), HookVal::List(Vec::new()))]);
        assert!(legacy.bindings(&listed).is_empty());
        assert!(legacy.unresolved().is_empty());
    }

    #[test]
    fn a_windows_short_name_is_asked_for() {
        let mut legacy = legacy(true);
        let short = HookVal::Dict(vec![(
            "hooks".into(),
            HookVal::Dict(vec![(
                "PreToolUse".into(),
                HookVal::List(vec![HookVal::Dict(vec![
                    ("matcher".into(), HookVal::Str("*".into())),
                    (
                        "hooks".into(),
                        HookVal::List(vec![HookVal::Dict(vec![(
                            "command".into(),
                            HookVal::Str(r"C:\PROGRA~1\Guard\python.exe -I bridge.py".into()),
                        )])]),
                    ),
                ])]),
            )]),
        )]);
        legacy.bindings(&short);
        assert_eq!(
            legacy.unresolved(),
            vec![r"C:\PROGRA~1\Guard\python.exe".to_owned()]
        );
    }

    #[test]
    fn malformed_requests_are_refused() {
        let Value::Object(fields) = json!({"expected": "[]"}) else {
            unreachable!()
        };
        assert!(DetectLegacy::parse(&fields).is_none());
    }

    #[test]
    fn a_token_never_matches_a_payload_string() {
        let value = HookVal::List(vec![HookVal::Str("\0hol-guard-token-0".into())]);
        let tokens = Tokens::new(&value);
        assert!(!"\0hol-guard-token-0".starts_with(&tokens.prefix));
    }
}
