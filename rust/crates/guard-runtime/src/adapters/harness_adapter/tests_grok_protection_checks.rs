//! The Grok protection verdicts: the permission floor in `config.toml`, the
//! legacy home-prefix rules, and the warnings each gap raises.

use super::{has_legacy_deny_rules, hooks_ready, managed_config_active, Assessment, Facts};
use crate::grok_user_config::MANAGED_DENY_RULES;

const RULES: [&str; 2] = ["Read(**/.grok/auth/**)", "Read(**/.ssh/**)"];

fn config(deny: &str, compat: &str) -> String {
    format!(
        "# BEGIN HOL GUARD MANAGED GROK\n[permission]\ndeny = {deny}\n{compat}\n\
         [hooks]\nPreToolUse = []\n# END HOL GUARD MANAGED GROK\n"
    )
}

const COMPAT: &str = "[compat.claude]\nhooks = false\n[compat.cursor]\nhooks = false\n";
const BOTH: &str = r#"["Read(**/.grok/auth/**)", "Read(**/.ssh/**)"]"#;

/// Whether the config is active, with the backup hooks verifying or not.
fn active(text: &str, hooks: bool) -> bool {
    managed_config_active(text, &RULES, |events| {
        assert_eq!(events.len(), 4);
        hooks
    })
}

#[test]
fn a_config_with_every_rule_compat_off_and_backup_hooks_is_active() {
    assert!(active(&config(BOTH, COMPAT), true));
}

#[test]
fn backup_hooks_that_do_not_verify_leave_the_config_inactive() {
    assert!(!active(&config(BOTH, COMPAT), false));
}

#[test]
fn the_hook_events_are_asked_in_the_managed_order() {
    let text = "[permission]\ndeny = [\"Read(**/.grok/auth/**)\", \"Read(**/.ssh/**)\"]\n\
                [compat.claude]\nhooks = false\n[compat.cursor]\nhooks = false\n\
                [hooks]\nUserPromptSubmit = [{ hooks = [] }]\n";
    let asked = managed_config_active(text, &RULES, |events| {
        let present: Vec<bool> = events.iter().map(Option::is_some).collect();
        assert_eq!(present, vec![false, true, false, false]);
        true
    });
    assert!(asked);
}

#[test]
fn rules_outside_a_real_permission_deny_list_do_not_protect() {
    for table in [
        "[permission]\nallow = [\"Read(**/.grok/auth/**)\"]",
        "[other]\ndeny = [\"Read(**/.grok/auth/**)\"]",
        "deny = [\"Read(**/.grok/auth/**)\"]",
        "[permission]\ndeny = [] # Read(**/.grok/auth/**)",
        "[permission]\ndeny = \"Read(**/.grok/auth/**)\"",
        "[permission]\ndeny = [\"Read(**/.grok/auth/**)\"",
    ] {
        let text = format!(
            "# BEGIN HOL GUARD MANAGED GROK\n{table}\n{COMPAT}[hooks]\nPreToolUse = []\n\
             # END HOL GUARD MANAGED GROK\n"
        );
        assert!(!active(&text, true), "{table}");
    }
}

#[test]
fn an_inline_commented_deny_array_is_not_a_deny_list() {
    let text = config("[\n  # \"Read(**/.grok/auth/**)\"\n]", COMPAT);
    assert!(!active(&text, true));
}

#[test]
fn every_managed_rule_must_be_denied() {
    let one = r#"["Read(**/.grok/auth/**)"]"#;
    assert!(!active(&config(one, COMPAT), true));
    // A non-string entry never matches a rule.
    let mixed = r#"["Read(**/.grok/auth/**)", 3, "Read(**/.ssh/**)"]"#;
    assert!(active(&config(mixed, COMPAT), true));
}

#[test]
fn the_claude_and_cursor_hook_imports_must_be_off() {
    for compat in [
        "",
        "[compat.claude]\nhooks = false\n",
        "[compat.claude]\nhooks = false\n[compat.cursor]\nhooks = true\n",
        "[compat.claude]\nhooks = false\n[compat.cursor]\nhooks = 0\n",
        "[compat.claude]\nhooks = false\n[compat.cursor]\n",
        "compat = 1\n",
    ] {
        assert!(!active(&config(BOTH, compat), true), "{compat:?}");
    }
}

#[test]
fn the_hooks_table_is_required() {
    let text = format!("[permission]\ndeny = {BOTH}\n{COMPAT}");
    assert!(!active(&text, true));
    let scalar = format!("hooks = 1\n[permission]\ndeny = {BOTH}\n{COMPAT}");
    assert!(!active(&scalar, true));
}

#[test]
fn text_that_is_not_toml_is_inactive() {
    assert!(!active("", true));
    assert!(!active("[permission\ndeny = [", true));
    assert!(!active("a = 1\na = 2\n", true));
}

#[test]
fn a_legacy_home_prefix_rule_is_one_whose_tilde_spelling_is_denied() {
    let legacy = "[permission]\ndeny = [\"Read(~/.grok/auth/**)\"]\n";
    assert!(has_legacy_deny_rules(legacy, &RULES));
    // The rule itself being denied makes the tilde copy harmless.
    let both = "[permission]\ndeny = [\"Read(**/.grok/auth/**)\", \"Read(~/.grok/auth/**)\"]\n";
    assert!(!has_legacy_deny_rules(both, &RULES));
    assert!(!has_legacy_deny_rules("[permission]\ndeny = []\n", &RULES));
    assert!(!has_legacy_deny_rules(
        "deny = [\"Read(~/.grok/auth/**)\"]",
        &RULES
    ));
    assert!(!has_legacy_deny_rules("not toml [", &RULES));
    // A rule that is not a `Read(**/` rule has no legacy spelling.
    assert!(!has_legacy_deny_rules(
        "[permission]\ndeny = [\"Bash(~/x)\"]\n",
        &["Bash(**/x)"]
    ));
}

#[test]
fn the_shipped_rules_have_a_legacy_spelling_to_detect() {
    let tilde = MANAGED_DENY_RULES
        .iter()
        .find(|rule| rule.starts_with("Read(**/"))
        .expect("a Read rule")
        .replacen("**/", "~/", 1);
    let text = format!("[permission]\ndeny = [\"{tilde}\"]\n");
    assert!(has_legacy_deny_rules(&text, &MANAGED_DENY_RULES));
}

fn facts() -> Facts {
    Facts {
        pretool_file: true,
        prompt_file: true,
        pretool_catchall: true,
        prompt_observe: true,
        config_is_file: true,
        config_unreadable: false,
        legacy_rules: false,
        managed_active: true,
        shim_installed: true,
        shim_dir: "/g/bin".to_owned(),
    }
}

fn warnings(change: impl FnOnce(&mut Facts)) -> Vec<String> {
    let mut facts = facts();
    change(&mut facts);
    Assessment::new(facts).warnings
}

#[test]
fn a_fully_protected_machine_has_no_warning() {
    let assessment = Assessment::new(facts());
    assert!(assessment.warnings.is_empty());
    assert_eq!(assessment.to_json()["ready"], true);
    assert!(hooks_ready(&assessment));
}

#[test]
fn a_missing_hook_file_is_the_connect_instruction() {
    let found = warnings(|facts| facts.prompt_file = false);
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("missing from ~/.grok/hooks/"));
    assert!(found[0].contains("apps connect grok"));
}

#[test]
fn a_stale_pretool_hook_and_a_missing_prompt_gate_are_repair_instructions() {
    let stale = warnings(|facts| facts.pretool_catchall = false);
    assert!(stale[0].contains("stale per-tool matcher list"));
    let prompt = warnings(|facts| facts.prompt_observe = false);
    assert!(prompt[0].contains("prompt gate or lifecycle hooks are missing"));
    // Only the first hook problem is reported.
    let both = warnings(|facts| {
        facts.pretool_catchall = false;
        facts.prompt_observe = false;
    });
    assert_eq!(both.len(), 1);
}

#[test]
fn the_config_warnings_are_exclusive_and_ordered() {
    let unreadable = warnings(|facts| {
        facts.config_unreadable = true;
        facts.legacy_rules = true;
        facts.managed_active = false;
    });
    assert_eq!(unreadable.len(), 1);
    assert!(unreadable[0].contains("could not be read"));
    let legacy = warnings(|facts| {
        facts.legacy_rules = true;
        facts.managed_active = false;
    });
    assert!(legacy[0].contains("literal home prefixes"));
    let stale = warnings(|facts| facts.managed_active = false);
    assert!(stale[0].contains("missing or stale in .grok/config.toml"));
    let absent = warnings(|facts| facts.config_is_file = false);
    assert!(absent[0].contains("missing or stale in .grok/config.toml"));
}

#[test]
fn a_missing_shim_names_its_directory_and_does_not_block_hook_readiness() {
    let mut missing = facts();
    missing.shim_installed = false;
    let assessment = Assessment::new(missing);
    assert!(assessment.warnings[0].contains("Add /g/bin to PATH"));
    assert_eq!(assessment.to_json()["ready"], false);
    assert_eq!(assessment.to_json()["launch_shim_installed"], false);
    assert!(hooks_ready(&assessment));
}

#[test]
fn hook_readiness_needs_files_active_config_and_no_hook_warning() {
    for change in [
        (|facts: &mut Facts| facts.pretool_catchall = false) as fn(&mut Facts),
        |facts| facts.prompt_file = false,
        |facts| facts.managed_active = false,
        |facts| facts.prompt_observe = false,
    ] {
        let mut broken = facts();
        change(&mut broken);
        assert!(!hooks_ready(&Assessment::new(broken)));
    }
}

#[test]
fn the_checks_keep_the_keys_the_cli_shows() {
    let json = Assessment::new(facts()).to_json();
    let keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![
            "launch_shim_installed",
            "managed_config_installed",
            "pretool_catchall_installed",
            "pretool_hook_installed",
            "prompt_hook_installed",
            "ready",
            "warnings",
        ]
    );
}
