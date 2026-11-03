//! The starter policies `hol-guard policy init` writes.
//!
//! They mirror the Policy Studio starter gallery, so a policy begun in the
//! browser and one begun with `policy init` read the same.
//! `docs/policy/STARTERS.md` lists the cross-reference.

use serde_json::{json, Value};

use super::values::{failure, Error};

struct Event {
    harness: &'static str,
    tool: Option<&'static str>,
    artifact: Option<&'static str>,
}

struct Rule {
    slug: &'static str,
    effect: &'static str,
    description: &'static str,
    match_field: &'static str,
    match_values: &'static [&'static str],
    example_name: &'static str,
    example: Event,
}

struct Starter {
    id: &'static str,
    name: &'static str,
    summary: &'static str,
    defaults: &'static [(&'static str, &'static str)],
    rules: &'static [&'static Rule],
}

const COMPROMISED_PACKAGES: &[&str] = &[
    "pkg:npm/event-stream",
    "pkg:npm/flatmap-stream",
    "pkg:npm/ua-parser-js",
];

const BLOCK_ENV_SECRETS: Rule = Rule {
    slug: "env-secrets",
    effect: "block",
    description: "Agents may not read environment variables, where API keys usually live.",
    match_field: "tools",
    match_values: &["prompt-env-read"],
    example_name: "Codex reads environment variables",
    example: Event {
        harness: "codex",
        tool: Some("prompt-env-read"),
        artifact: None,
    },
};
const BLOCK_SECRET_FILES: Rule = Rule {
    slug: "secret-files",
    effect: "block",
    description: "Agents may not read files into prompts.",
    match_field: "tools",
    match_values: &["prompt-file"],
    example_name: "Claude Code reads a file into a prompt",
    example: Event {
        harness: "claude-code",
        tool: Some("prompt-file"),
        artifact: None,
    },
};
const BLOCK_COMPROMISED: Rule = Rule {
    slug: "compromised-packages",
    effect: "block",
    description: "Known compromised npm packages.",
    match_field: "artifacts",
    match_values: COMPROMISED_PACKAGES,
    example_name: "Installing event-stream",
    example: Event {
        harness: "codex",
        tool: None,
        artifact: Some("pkg:npm/event-stream"),
    },
};
const BLOCK_MCP_SERVERS: Rule = Rule {
    slug: "mcp-servers",
    effect: "block",
    description: "Agents may not start MCP servers until this rule is narrowed or removed.",
    match_field: "tools",
    match_values: &["mcp"],
    example_name: "Cursor starts an MCP server",
    example: Event {
        harness: "cursor",
        tool: Some("mcp"),
        artifact: None,
    },
};

const STARTERS: &[Starter] = &[
    Starter {
        id: "safe-defaults",
        name: "Safe defaults",
        summary: "Blocks agents from reading environment variables; unknown publishers default to block.",
        defaults: &[
            ("mode", "prompt"),
            ("defaultAction", "warn"),
            ("unknownPublisherAction", "block"),
        ],
        rules: &[&BLOCK_ENV_SECRETS],
    },
    Starter {
        id: "package-firewall",
        name: "Package firewall",
        summary: "Blocks known compromised packages and sets new publishers to review in the defaults.",
        defaults: &[
            ("mode", "enforce"),
            ("defaultAction", "warn"),
            ("unknownPublisherAction", "review"),
        ],
        rules: &[&BLOCK_COMPROMISED],
    },
    Starter {
        id: "secrets-guard",
        name: "Secrets guard",
        summary: "Blocks agents from reading environment variables or files into a prompt.",
        defaults: &[
            ("mode", "prompt"),
            ("defaultAction", "allow"),
            ("unknownPublisherAction", "review"),
        ],
        rules: &[&BLOCK_ENV_SECRETS, &BLOCK_SECRET_FILES],
    },
    Starter {
        id: "mcp-guard",
        name: "MCP server guard",
        summary: "Blocks agents from starting MCP servers until you narrow or remove the rule.",
        defaults: &[
            ("mode", "prompt"),
            ("defaultAction", "allow"),
            ("unknownPublisherAction", "review"),
        ],
        rules: &[&BLOCK_MCP_SERVERS],
    },
    Starter {
        id: "team-baseline",
        name: "Team baseline",
        summary: "A shared floor for every device: compromised packages and secret reads are blocked outright.",
        defaults: &[
            ("mode", "enforce"),
            ("defaultAction", "warn"),
            ("unknownPublisherAction", "review"),
        ],
        rules: &[&BLOCK_COMPROMISED, &BLOCK_ENV_SECRETS],
    },
    Starter {
        id: "blank",
        name: "Blank",
        summary: "No rules. Guard asks at the device and you add rules as you learn what your agents do.",
        defaults: &[("mode", "prompt")],
        rules: &[],
    },
];

/// Events no starter rule matches, so each starter can show the default
/// outcome as a second example.
const FALLTHROUGH_EXAMPLES: &[(&str, &str, Event)] = &[
    (
        "fallthrough-package",
        "An unlisted package falls through to the defaults",
        Event {
            harness: "codex",
            tool: None,
            artifact: Some("pkg:npm/left-pad"),
        },
    ),
    (
        "fallthrough-shell",
        "An unlisted tool falls through to the defaults",
        Event {
            harness: "codex",
            tool: Some("shell"),
            artifact: None,
        },
    ),
];

const POLICY_MODELINE: &str =
    "# yaml-language-server: $schema=https://hol.org/schema/policy/v1alpha1";

/// `{"id","name","summary"}` for every starter, in gallery order.
pub(super) fn list() -> Value {
    let listing: Vec<Value> = STARTERS
        .iter()
        .map(|starter| json!({"id":starter.id,"name":starter.name,"summary":starter.summary}))
        .collect();
    Value::Array(listing)
}

/// The text of a new `guard-policy.yaml` for `input.id`, or null for an
/// unknown starter. `input.created_at` stamps each rule's provenance.
pub(super) fn render(input: &Value) -> Result<Value, Error> {
    let fields = input
        .as_object()
        .filter(|fields| fields.len() == 2)
        .ok_or_else(|| failure("TypeError", "policy_starter_request", None))?;
    let (Some(id), Some(created_at)) = (
        fields.get("id").and_then(Value::as_str),
        fields.get("created_at").and_then(Value::as_str),
    ) else {
        return Err(failure("TypeError", "policy_starter_request", None));
    };
    if !is_utc_second(created_at) {
        return Err(failure("ValueError", "policy_starter_created_at", None));
    }
    Ok(STARTERS
        .iter()
        .find(|starter| starter.id == id)
        .map_or(Value::Null, |starter| {
            Value::String(starter_yaml(starter, created_at))
        }))
}

/// `YYYY-MM-DDTHH:MM:SSZ`, the only stamp a starter writes.
fn is_utc_second(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

fn quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\u{8}' => quoted.push_str("\\b"),
            '\u{c}' => quoted.push_str("\\f"),
            '\u{20}'..='\u{7f}' => quoted.push(character),
            _ => {
                let mut units = [0_u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    quoted.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    quoted.push('"');
    quoted
}

fn event_lines(lines: &mut Vec<String>, event: &Event, indent: &str) {
    lines.push(format!("{indent}harness: {}", event.harness));
    if let Some(tool) = event.tool {
        lines.push(format!("{indent}tool: {tool}"));
    }
    if let Some(artifact) = event.artifact {
        lines.push(format!("{indent}artifact: {artifact}"));
    }
}

fn starter_yaml(starter: &Starter, created_at: &str) -> String {
    let id = starter.id;
    let mut lines: Vec<String> = vec![
        POLICY_MODELINE.to_owned(),
        "# Edit the rules, then run: hol-guard policy test guard-policy.yaml".to_owned(),
        "apiVersion: guard.hashgraphonline.com/v1alpha1".to_owned(),
        "kind: GuardPolicy".to_owned(),
        "metadata:".to_owned(),
        format!("  id: policy.{id}"),
        format!("  name: {}", quote(starter.name)),
        "  revision: 1".to_owned(),
        "spec:".to_owned(),
        "  defaults:".to_owned(),
    ];
    for (key, value) in starter.defaults {
        lines.push(format!("    {key}: {value}"));
    }
    lines.push(if starter.rules.is_empty() {
        "  rules: []".to_owned()
    } else {
        "  rules:".to_owned()
    });
    for rule in starter.rules {
        lines.push(format!("    - id: rule-{id}-{}", rule.slug));
        lines.push(format!("      description: {}", quote(rule.description)));
        lines.push("      enabled: true".to_owned());
        lines.push(format!("      effect: {}", rule.effect));
        lines.push("      match:".to_owned());
        lines.push(format!("        {}:", rule.match_field));
        for value in rule.match_values {
            lines.push(format!("          - {value}"));
        }
        lines.push("      lifetime:".to_owned());
        lines.push("        mode: permanent".to_owned());
        lines.push("      provenance:".to_owned());
        lines.push("        source: builder".to_owned());
        lines.push(format!("        createdAt: {created_at}"));
    }
    lines.push("  x-hol.tests:".to_owned());
    for rule in starter.rules {
        lines.push(format!("    - id: test-{id}-{}", rule.slug));
        lines.push(format!("      name: {}", quote(rule.example_name)));
        lines.push("      event:".to_owned());
        event_lines(&mut lines, &rule.example, "        ");
        lines.push("      expect:".to_owned());
        lines.push(format!("        effect: {}", rule.effect));
        lines.push(format!("        ruleId: rule-{id}-{}", rule.slug));
    }
    let fallthrough = 2_usize.saturating_sub(starter.rules.len());
    for (test_id, name, event) in FALLTHROUGH_EXAMPLES.iter().take(fallthrough) {
        lines.push(format!("    - id: test-{id}-{test_id}"));
        lines.push(format!("      name: {}", quote(name)));
        lines.push("      event:".to_owned());
        event_lines(&mut lines, event, "        ");
        lines.push("      expect:".to_owned());
        lines.push("        effect: default".to_owned());
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

#[cfg(test)]
#[path = "policy_document_starters_tests.rs"]
mod tests;
