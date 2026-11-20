//! Apps whose prompts can carry CIGAR's project context.

use std::path::Path;

use serde_json::Value;

/// Apps whose prompt hook passes Guard's added context to the model. Copilot
/// CLI and Grok drop what an allowing prompt hook adds, Cursor's prompt hook
/// can only allow or block, and Guard has no prompt hook in the rest.
pub(crate) const CIGAR_APPS: [&str; 9] = [
    "claude-code",
    "codex",
    "pi",
    "omp",
    "devin",
    "muse",
    "zcode",
    "kimi",
    "cline",
];

/// The apps that take CIGAR's context in this Guard home. Cline only asks
/// Guard about prompts through its native hooks; when Guard is set up through
/// the Cline plugin instead, no prompt reaches Guard and CIGAR can't run there.
pub(crate) fn cigar_apps(guard_home: &Path) -> Vec<&'static str> {
    let cline_plugin = cline_transport(guard_home).as_deref() == Some("plugin");
    CIGAR_APPS
        .into_iter()
        .filter(|app| !(cline_plugin && *app == "cline"))
        .collect()
}

/// The Cline transport Guard installed, as its adapter state records it.
fn cline_transport(guard_home: &Path) -> Option<String> {
    let path = guard_home
        .join("managed")
        .join("cline")
        .join("adapter-state.json");
    let state: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
    state.get("active_transport")?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(name: &str, transport: Option<&str>) -> std::path::PathBuf {
        let home = std::env::temp_dir().join(format!("cigar-apps-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let managed = home.join("managed").join("cline");
        std::fs::create_dir_all(&managed).unwrap();
        if let Some(transport) = transport {
            let state = serde_json::json!({ "active_transport": transport });
            std::fs::write(managed.join("adapter-state.json"), state.to_string()).unwrap();
        }
        home
    }

    #[test]
    fn cline_takes_context_only_through_its_native_hooks() {
        assert!(cigar_apps(&home("unset", None)).contains(&"cline"));
        assert!(cigar_apps(&home("hooks", Some("hooks"))).contains(&"cline"));
        let plugin = cigar_apps(&home("plugin", Some("plugin")));
        assert!(!plugin.contains(&"cline"));
        assert!(plugin.contains(&"kimi") && plugin.contains(&"codex"));
    }
}
