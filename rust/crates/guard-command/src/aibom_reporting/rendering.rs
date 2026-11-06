use super::*;

/// `_aibom_connection_status(store)`
pub fn _aibom_connection_status(deps: &ReportingDeps<'_>) -> String {
    if deps.store.get_cloud_sync_profile().is_none() {
        return "not_connected".to_string();
    }
    if deps.store.get_cloud_workspace_id().is_none() {
        return "workspace_required".to_string();
    }
    let sync_summary = deps.api._sync_summary(deps.store);
    if sync_summary.get("synced").and_then(Value::as_bool) == Some(true)
        && sync_summary
            .get("synced_at")
            .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.is_empty()))
    {
        return "synced".to_string();
    }
    "sync_required".to_string()
}

/// `_markdown_table_cell(value)`
pub(super) fn _markdown_table_cell(value: &Value) -> String {
    // `html.escape(" ".join(str(value).splitlines()), quote=False)` — collapse
    // newlines to spaces, then `&` `<` `>` escaping, then markdown punct escape.
    let raw = value_display(value);
    let joined = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let escaped = joined
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    static MD_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"([\\|`*_\[\]()!~])").expect("md cell re"));
    MD_RE.replace_all(&escaped, "\\$1").to_string()
}

/// `_render_aibom_markdown(payload)`
pub fn _render_aibom_markdown(payload: &Map<String, Value>) -> String {
    let layer_summary = payload.get("layer_summary");
    let trust_summary = payload.get("trust_summary");
    let mut lines: Vec<String> = vec![
        "# HOL Guard AIBOM".to_string(),
        String::new(),
        "## Layer summary".to_string(),
        String::new(),
    ];
    if let Some(layer_summary) = layer_summary.and_then(Value::as_object) {
        let get = |k: &str| layer_summary.get(k).cloned().unwrap_or(json!(0));
        for line in [
            format!("- Instructions: {}", value_display(&get("instructions"))),
            format!("- Skills: {}", value_display(&get("skills"))),
            format!("- MCP: {}", value_display(&get("mcp"))),
            format!("- Plugins: {}", value_display(&get("plugins"))),
            format!("- Policies: {}", value_display(&get("policies"))),
            format!("- Findings: {}", value_display(&get("findings"))),
            format!("- Trust: {}", value_display(&get("trust"))),
            format!("- Sources: {}", value_display(&get("sources"))),
            format!("- Drift: {}", value_display(&get("driftCount"))),
            String::new(),
        ] {
            lines.push(line);
        }
    }
    lines.push("## Artifacts".to_string());
    lines.push(String::new());
    lines.push("| Artifact | Harness | Type | Scope | Verdict | Present |".to_string());
    lines.push("| --- | --- | --- | --- | --- | --- |".to_string());
    if let Some(artifacts) = payload.get("artifacts").and_then(Value::as_array) {
        for item in artifacts {
            let item = match item.as_object() {
                Some(i) => i,
                None => continue,
            };
            let mut cells: Vec<String> = [
                "artifact_name",
                "harness",
                "artifact_type",
                "source_scope",
                "trust_verdict",
            ]
            .iter()
            .map(|field| {
                _markdown_table_cell(item.get(*field).unwrap_or(&Value::String(String::new())))
            })
            .collect();
            cells.push(
                if item
                    .get("present")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    "yes"
                } else {
                    "no"
                }
                .to_string(),
            );
            lines.push(format!("| {} |", cells.join(" | ")));
        }
    }
    if let Some(trust_summary) = trust_summary.and_then(Value::as_object) {
        let get = |k: &str| trust_summary.get(k).cloned().unwrap_or(json!(0));
        lines.push(String::new());
        lines.push("## Trust coverage".to_string());
        lines.push(String::new());
        lines.push(format!(
            "- Covered: {} / {}",
            value_display(&get("covered")),
            value_display(&get("eligible"))
        ));
        lines.push(format!(
            "- Coverage: {}%",
            value_display(&get("coverage_percent"))
        ));
        lines.push(String::new());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// `round()` — Python banker's rounding for floats.
pub(super) fn py_round_f64(value: f64) -> i64 {
    if !value.is_finite() {
        return 0;
    }
    let floor = value.floor();
    let diff = value - floor;
    let base = floor as i64;
    if diff < 0.5 {
        base
    } else if diff > 0.5 {
        base + 1
    } else if base % 2 == 0 {
        base
    } else {
        base + 1
    }
}
