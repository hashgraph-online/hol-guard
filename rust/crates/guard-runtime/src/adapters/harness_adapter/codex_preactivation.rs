//! Codex: the inventory an install checks over each hook source before it
//! writes anything (`_require_complete_preactivation_inventory`).
//!
//! The request carries one source's `hooks` and the manifest's `owned`
//! bindings as `_Wire` text, the `tokens` that text names, the source's
//! `source_path`, `scope`, `format` and `hooks_enabled`, the `legacy` fields
//! and the install a handler must belong to. This selects the current
//! package's legacy registrations and the handlers an earlier generation of
//! this install left, walks the source with them, and refuses as Python
//! does: the first issue, then unmanaged executable hooks a disabled source
//! would switch on. The answer is `{"owners": [...]}`, every active handler
//! with a command, for the owner check an install runs next.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use super::codex::{flag, text};
use super::codex_merge::{get, Entries};
use super::codex_owner_home::{self_bindings, Home};
use super::codex_owners::Legacy;
use super::{Failure, Step};
use crate::codex_hooks::{walk, Bindings, Ownership, Record, Source};
use crate::codex_value::{token_value, HookVal};
use crate::cursor_hook_command::Syntax;
use crate::pyjson::{self, PyVal};

/// The request fields beyond the legacy and install ones.
pub(super) const FIELDS: [&str; 7] = [
    "hooks",
    "owned",
    "tokens",
    "source_path",
    "scope",
    "format",
    "hooks_enabled",
];
const UNIDENTIFIED: &str = "native_codex_hook_identity_unavailable";
const UNIDENTIFIED_MESSAGE: &str = "Guard's native runtime did not identify this source's Codex \
     hooks. Repair whichever the code names, the Guard installation or the hook definition, \
     before retrying install.";
const UNMANAGED: &str = "codex_hook_inventory_unmanaged_executable";

pub(super) fn answer(fields: &Map<String, Value>, syntax: &mut Syntax) -> Step<Value> {
    let hooks = parse(fields, "hooks")?;
    let PyVal::List(owned) = parse(fields, "owned")? else {
        return Err(Failure::Invalid);
    };
    let tokens = tokens(fields)?;
    let path = text(fields, "source_path")?;
    let format = match text(fields, "format")? {
        "json" => "json",
        "toml" => "toml",
        _ => return Err(Failure::Invalid),
    };
    let enabled = flag(fields, "hooks_enabled")?;
    let (legacy, home) = (Legacy::parse(fields)?, Home::parse(fields)?);
    let entries: Entries = match &hooks {
        PyVal::Dict(entries) => entries.clone(),
        _ => Vec::new(),
    };
    let legacy = values(legacy.bindings(&entries, syntax))?;
    let self_bound = values(self_bindings(&entries, &home, &recorded(&owned), syntax))?;
    let authenticated = values(owned)?;
    // `enumerate_codex_hooks`: no hooks is nothing to walk, and hooks that
    // are not a table reach the walk as the null the wire leaves of them.
    let walked = match &hooks {
        PyVal::Null => None,
        PyVal::Dict(_) => Some(hook_val(&hooks, &tokens).ok_or(Failure::Invalid)?),
        _ => Some(HookVal::Null),
    };
    let source = Source {
        path,
        scope: text(fields, "scope")?,
        format,
        hooks_enabled: enabled,
    };
    let bindings = Bindings {
        authenticated: &authenticated,
        legacy: &legacy,
        self_bound: &self_bound,
        tokens: &tokens,
    };
    let inventory = walk(walked.as_ref(), source, bindings);
    if inventory.records.iter().any(|record| record.unencodable) {
        let refusal = format!("{UNIDENTIFIED}: {path} in {path}. {UNIDENTIFIED_MESSAGE}");
        return Err(Failure::Runtime(refusal));
    }
    if let Some(issue) = inventory.issues.first() {
        return Err(Failure::Runtime(issue.warning(path)));
    }
    let unmanaged: Vec<String> = inventory
        .records
        .iter()
        .filter(|record| {
            record.active && record.executable && record.ownership == Ownership::Unmanaged
        })
        .map(Record::coordinate)
        .collect();
    if !enabled && !unmanaged.is_empty() {
        return Err(Failure::Runtime(format!(
            "{UNMANAGED}: Guard refused to enable existing Codex hook entries without explicit \
             approval; unmanaged executable hooks are present at {} in {path}. Review or remove \
             those hooks before running install.",
            unmanaged.join(", ")
        )));
    }
    let owners: Vec<Value> = inventory
        .records
        .iter()
        .filter(|record| record.active)
        .filter_map(|record| {
            Some(json!({
                "command": record.command.as_ref()?,
                "ownership": ownership_name(record.ownership),
                "coordinate": record.coordinate(),
            }))
        })
        .collect();
    Ok(json!({ "owners": owners }))
}

fn parse(fields: &Map<String, Value>, key: &str) -> Step<PyVal> {
    pyjson::parse(text(fields, key)?).map_err(|_| Failure::Invalid)
}

fn tokens(fields: &Map<String, Value>) -> Step<BTreeMap<String, Value>> {
    let tokens = fields
        .get("tokens")
        .and_then(Value::as_object)
        .ok_or(Failure::Invalid)?;
    Ok(tokens
        .iter()
        .map(|(token, meaning)| (token.clone(), meaning.clone()))
        .collect())
}

/// `_recorded_handler_commands`: the handler commands the manifest records.
fn recorded(owned: &[PyVal]) -> BTreeSet<String> {
    owned
        .iter()
        .filter_map(PyVal::as_dict)
        .filter_map(|binding| get(binding, "handler")?.as_dict())
        .filter_map(|handler| get(handler, "command")?.as_str())
        .map(str::to_owned)
        .collect()
}

/// Bindings as the walk reads them; a token stays the string it is.
fn values(bindings: Vec<PyVal>) -> Step<Vec<Value>> {
    bindings
        .iter()
        .map(|binding| binding.to_json().ok_or(Failure::Invalid))
        .collect()
}

/// The source value as the parser handed it to Python: a token is the
/// scalar it stands for, and one naming nothing a source can hold refuses.
fn hook_val(value: &PyVal, tokens: &BTreeMap<String, Value>) -> Option<HookVal> {
    Some(match value {
        PyVal::Null => HookVal::Null,
        PyVal::Bool(flag) => HookVal::Bool(*flag),
        PyVal::Int(digits) => HookVal::Int(digits.clone()),
        PyVal::Float(number) => HookVal::Float(*number),
        PyVal::Str(text) => match tokens.get(text) {
            Some(meaning) => token_value(meaning)?,
            None => HookVal::Str(text.clone()),
        },
        PyVal::List(items) => HookVal::List(
            items
                .iter()
                .map(|item| hook_val(item, tokens))
                .collect::<Option<_>>()?,
        ),
        PyVal::Dict(entries) => HookVal::Dict(
            entries
                .iter()
                .map(|(key, item)| Some((key.clone(), hook_val(item, tokens)?)))
                .collect::<Option<_>>()?,
        ),
    })
}

fn ownership_name(ownership: Ownership) -> &'static str {
    match ownership {
        Ownership::AuthenticatedManifest => "authenticated_manifest",
        Ownership::ExactLegacyAdoption => "exact_legacy_adoption",
        Ownership::SelfInstallBinding => "self_install_binding",
        Ownership::Unmanaged => "unmanaged",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::super::codex_owners::dispatch;
    use super::super::{Failure, Step};

    const COMMAND: &str = "/opt/tools/lint-hook";

    fn ask(hooks: &Value, owned: &Value, enabled: bool) -> Step<Value> {
        let request = json!({
            "op": "preactivation",
            "windows": false,
            "long_paths": {},
            "hooks": hooks.to_string(),
            "owned": owned.to_string(),
            "tokens": {},
            "source_path": "/home/u/.codex/config.toml",
            "scope": "global",
            "format": "toml",
            "hooks_enabled": enabled,
            "cwd": "/home/u",
            "guard_home": "/home/u/.hol-guard",
            "package_root": "/opt/guard/site-packages",
            "expected": "[]",
            "argv": ["/opt/guard/bin/python", "-I", "/opt/guard/bridge.py"],
            "legacy_argv": ["/usr/bin/python3", "-I", "/opt/guard/bridge.py"],
            "statuses": ["HOL Guard reviewing"],
        });
        dispatch(request.as_object().unwrap())
    }

    fn hooks() -> Value {
        json!({"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": COMMAND}]}]})
    }

    fn refusal(step: Step<Value>) -> String {
        match step {
            Err(Failure::Runtime(message)) => message,
            _ => panic!("expected a refusal"),
        }
    }

    #[test]
    fn an_enabled_source_reports_its_active_owners() {
        let answer = ask(&hooks(), &json!([]), true).unwrap_or_else(|_| panic!("refused"));
        assert_eq!(
            answer,
            json!({"owners": [{
                "command": COMMAND,
                "ownership": "unmanaged",
                "coordinate": "PreToolUse/group[0]/handler[0]",
            }]})
        );
    }

    #[test]
    fn a_disabled_source_refuses_unmanaged_executables() {
        let message = refusal(ask(&hooks(), &json!([]), false));
        assert!(message.starts_with("codex_hook_inventory_unmanaged_executable: "));
        assert!(message
            .contains("present at PreToolUse/group[0]/handler[0] in /home/u/.codex/config.toml."));
    }

    #[test]
    fn an_authenticated_handler_is_owned_even_when_disabled() {
        let handler = json!({"type": "command", "command": COMMAND});
        let owned = json!([{"event": "PreToolUse", "group": {"matcher": "*"}, "handler": handler}]);
        let answer = ask(&hooks(), &owned, false).unwrap_or_else(|_| panic!("refused"));
        assert_eq!(answer["owners"][0]["ownership"], "authenticated_manifest");
    }

    #[test]
    fn hooks_that_are_not_a_table_are_the_first_issue() {
        let message = refusal(ask(&json!(["x"]), &json!([]), true));
        assert!(message.contains(": /home/u/.codex/config.toml in /home/u/.codex/config.toml. "));
        assert_eq!(
            ask(&Value::Null, &json!([]), false).ok(),
            Some(json!({"owners": []}))
        );
    }
}
