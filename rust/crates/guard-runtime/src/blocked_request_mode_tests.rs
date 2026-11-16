use super::*;

#[test]
fn connector_setup_reason_matches_the_python_vectors_byte_for_byte() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../testdata/connector_setup_reason_vectors.json"
    ))
    .expect("vectors");
    for case in vectors.as_array().expect("cases") {
        let permitted: Vec<&str> = case["permitted"]
            .as_array()
            .expect("permitted")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        let text = connector_setup_reason(
            case["name"].as_str().expect("name"),
            case["surface"].as_str().expect("surface"),
            case["ask"].as_bool().expect("ask"),
            &permitted,
            case["approvable"].as_bool().expect("approvable"),
        );
        assert_eq!(text, case["text"].as_str().expect("text"));
        let unlinked = case["unlinked"].as_bool().expect("unlinked");
        assert_eq!(
            is_unlinked_connector_setup_reason(&text),
            unlinked,
            "{text}"
        );
        assert!(!text.contains("http"), "{text}");
        assert_eq!(
            text.ends_with(SAFE_ALTERNATIVE_GUIDANCE),
            unlinked,
            "{text}"
        );
        assert_eq!(
            text.contains("hol-guard approvals"),
            !unlinked,
            "an unlinked text never points at the inbox: {text}"
        );
    }
}

#[test]
fn review_drops_the_inbox_offer_only_when_approval_cannot_let_it_run() {
    let native = "HOL Guard requires review because this command could not be confirmed \
         read-only. Approve it in the HOL Guard inbox (choose Always for a repeated read-only \
         command), or split it into simpler commands.";
    for (queued, reuses, offered) in [
        (true, false, false),
        (false, true, false),
        (true, true, true),
    ] {
        let text = safe_alternative_reason_with_retry(
            native,
            Some("native_command_review_required"),
            Some(queued),
            reuses,
            false,
        );
        assert!(text.starts_with(
            "HOL Guard requires review because this command could not be confirmed read-only."
        ));
        assert_eq!(text.contains("Approve it in the HOL Guard inbox"), offered);
    }
}

#[test]
fn a_waiting_review_says_what_each_approval_choice_covers() {
    let scope = "Allow once lets this exact action run one time; Always allow keeps allowing \
         it until the user removes that choice.";
    // The two choices are named only where a one-time approval lets the retry run.
    for (queued, reuses, exact, named) in [
        (true, true, false, true),
        (true, false, true, false),
        (true, false, false, false),
        (false, true, true, false),
    ] {
        let text = safe_alternative_reason_with_retry(
            "Needs review.",
            Some("native_network_review"),
            Some(queued),
            reuses,
            exact,
        );
        assert_eq!(text.contains(scope), named, "{text}");
    }
}

#[test]
fn the_hold_names_only_a_plain_rule_identifier() {
    let named = safe_alternative_reason("Held.", Some("native_network_review"), Some(true));
    assert!(
        named.contains("Guard rule: `native_network_review`."),
        "{named}"
    );
    let long = "x".repeat(65);
    for code in ["unknown", "", "Native-Rule", "a`b", long.as_str()] {
        let text = safe_alternative_reason("Held.", Some(code), Some(true));
        assert!(!text.contains("Guard rule:"), "{text}");
    }
}

#[test]
fn a_direct_read_review_leaves_out_the_search_advice() {
    let read = "HOL Guard requires review before this file read can execute. `src/lib/auth` \
         is named like a credential store, so Guard holds a read of it.";
    let text = safe_alternative_reason(read, Some("native_file_read_review"), Some(true));
    assert!(text.starts_with(read));
    assert!(!text.contains("A search is checked"), "{text}");
    let search = safe_alternative_reason(
        "HOL Guard requires review before this file action can execute.",
        Some("native_file_read_review"),
        Some(true),
    );
    assert!(search.contains("A search is checked"), "{search}");
}

#[test]
fn a_build_review_leaves_out_the_install_hint() {
    let build = "HOL Guard requires review before this build or test command can execute, \
         because it can download dependencies and run their build scripts.";
    let text = safe_alternative_reason(build, Some("native_package_review"), Some(true));
    assert!(text.starts_with(build));
    assert!(!text.contains("--ignore-scripts"), "{text}");
    let install = safe_alternative_reason(
        "HOL Guard requires review before this package or script command can execute.",
        Some("native_package_review"),
        Some(true),
    );
    assert!(install.contains("--ignore-scripts"), "{install}");
}

/// Guard tells the agent which install form can proceed. Every form it
/// names has to be one the native authority actually proves script-free,
/// or the advice sends the agent straight back into the same review. The
/// pnpm form needs `--ignore-pnpmfile` as well, because a `.pnpmfile.cjs`
/// hook runs its own code during the install.
#[test]
fn the_install_hint_names_the_managers_its_lockfile_forms_cover() {
    let hint = reason_code_hint("native_package_review");
    assert!(hint.contains("For npm, pnpm and bun, an install"), "{hint}");
    assert!(
        hint.contains("Other package managers, such as pip, uv or cargo, have no form"),
        "{hint}"
    );
}

#[test]
fn every_install_form_the_hint_names_is_one_guard_proves_script_free() {
    let hint = reason_code_hint("native_package_review");
    let forms: Vec<&str> = hint
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|form| form.contains("install") || form.contains(" ci"))
        .collect();
    assert_eq!(forms.len(), 3, "{hint}");
    for form in forms {
        assert!(
            guard_command::pretool::no_script_install_command(form),
            "the hint offers `{form}`, which Guard does not prove script-free"
        );
    }
}

#[test]
fn a_cloud_outage_pause_does_not_offer_the_lockfile_form() {
    let text = safe_alternative_reason(
        "HOL Guard requires review before this package or script command can execute.",
        Some("native_package_cloud_unavailable"),
        Some(true),
    );
    assert!(
        text.contains("Guard Cloud could not check this package"),
        "{text}"
    );
    assert!(!text.contains("--ignore-scripts"), "{text}");
}
