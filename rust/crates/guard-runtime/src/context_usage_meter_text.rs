//! The text `hol-guard context usage` prints: the meter's totals per tool,
//! then what CIGAR saved, labeled as an estimate.

use serde_json::Value;

const ROWS: [(&str, &str); 6] = [
    ("uncached_input_tokens", "Input at full price"),
    ("cached_input_tokens", "Input read from cache"),
    ("cache_write_tokens", "Input written to cache"),
    ("output_tokens", "Output"),
    ("requests", "Model requests"),
    ("compactions", "Chat summaries"),
];

fn name(harness: &str) -> String {
    match harness {
        "codex" => "Codex",
        "claude-code" => "Claude Code",
        "copilot" => "Copilot",
        "cursor" => "Cursor",
        "gemini" => "Gemini",
        "opencode" => "OpenCode",
        "pi" => "Pi",
        other => other,
    }
    .to_owned()
}

/// `value` with a comma every three digits.
pub(crate) fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn int(value: &Value, field: &str) -> u64 {
    value.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn text(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn list(value: &Value, field: &str) -> Vec<Value> {
    value
        .get(field)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn meter(state: &Value, lines: &mut Vec<String>) {
    let days = int(state, "window_days");
    lines.push(format!(
        "Model usage from each tool's own records on this computer, today and over the last {days} days."
    ));
    let today = list(state, "today");
    for tool in list(state, "week") {
        let harness = text(&tool, "harness");
        let label = name(&harness);
        lines.push(String::new());
        let sessions = int(&tool, "sessions");
        if sessions == 0 {
            lines.push(format!("{label}: no sessions in the last {days} days."));
            continue;
        }
        let noun = if sessions == 1 { "session" } else { "sessions" };
        lines.push(format!("{label}: {} {noun}", grouped(sessions)));
        lines.push(format!(
            "  {:24}{:>18}{:>20}",
            "",
            "Today",
            format!("Last {days} days")
        ));
        let now = today
            .iter()
            .find(|item| text(item, "harness") == harness)
            .and_then(|item| item.get("totals").cloned())
            .unwrap_or(Value::Null);
        let week = tool.get("totals").cloned().unwrap_or(Value::Null);
        for (field, row) in ROWS {
            lines.push(format!(
                "  {row:24}{:>18}{:>20}",
                grouped(int(&now, field)),
                grouped(int(&week, field))
            ));
        }
    }
    let names: Vec<String> = list(state, "unread")
        .iter()
        .filter_map(Value::as_str)
        .map(name)
        .collect();
    let unread = match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} or {last}", rest.join(", ")),
        _ => names.concat(),
    };
    lines.push(String::new());
    lines.push(format!(
        "Guard does not read usage records from {unread}, so they are not counted here."
    ));
}

fn savings(report: &Value, lines: &mut Vec<String>) {
    lines.push(String::new());
    if report.is_null() {
        lines.push(
            "Guard's background service did not answer, so it cannot estimate what CIGAR saved."
                .to_owned(),
        );
        return;
    }
    let total = report.get("total").cloned().unwrap_or(Value::Null);
    let days = int(report, "window_days");
    let sessions = int(&total, "sessions");
    if sessions == 0 {
        lines.push(format!(
            "CIGAR has not handed code to a prompt in the last {days} days, so there is nothing to estimate."
        ));
        return;
    }
    let measured = int(&total, "measured_sessions");
    if measured == 0 {
        lines.push(
            "CIGAR helped, but Guard could not read those sessions' records, so it cannot estimate yet."
                .to_owned(),
        );
    } else if int(&total, "used_tokens") == 0 {
        lines.push(
            "CIGAR helped, but those sessions' records show no tokens used, so Guard cannot estimate yet."
                .to_owned(),
        );
    } else {
        let saved = grouped(int(&total, "estimated_saved_tokens"));
        lines.push(format!(
            "CIGAR saved about {saved} tokens in the last {days} days. This is an estimate."
        ));
        if measured < sessions {
            lines.push(format!(
                "  The estimate covers {} of {} sessions. Guard could not read the rest.",
                grouped(measured),
                grouped(sessions)
            ));
        }
    }
    let prompts = int(&total, "prompts");
    let noun = if prompts == 1 { "prompt" } else { "prompts" };
    lines.push(format!(
        "  It handed {} {noun} about {} tokens of code.",
        grouped(prompts),
        grouped(int(&total, "context_tokens"))
    ));
    let checked = int(&total, "files_checked");
    if checked > 0 {
        lines.push(format!(
            "  Of {} files it showed, the agent opened {} again anyway.",
            grouped(checked),
            grouped(int(&total, "files_opened_anyway"))
        ));
    }
    let rates: Vec<String> = list(report, "apps")
        .iter()
        .map(|app| {
            let rate = app
                .get("rate_percent")
                .map_or(String::new(), Value::to_string);
            format!("{} {rate}%", name(&text(app, "app")))
        })
        .collect();
    lines.push(format!(
        "  How: the tokens those sessions used, and the share CIGAR saved on Guard's benchmark ({}).",
        rates.join(", ")
    ));
}

/// The meter's totals, then the savings estimate (`null` when the resident
/// did not answer).
pub(super) fn render(state: &Value, report: &Value) -> String {
    let mut lines = Vec::new();
    meter(state, &mut lines);
    savings(report, &mut lines);
    let mut out = lines.join("\n");
    out.push('\n');
    out
}
