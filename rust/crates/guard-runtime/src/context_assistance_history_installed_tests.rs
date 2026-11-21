use super::{
    workspace::{candidate, data},
    Fixture,
};
use serde_json::json;

#[test]
#[ignore = "requires the explicitly approved installed CIGAR 0.14.1 candidate"]
fn installed_history_survives_source_updates_but_never_withdrawal_clear_or_opt_out() {
    let fixture = Fixture::new();
    let off = data(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(off["history_entries"], 0);
    assert_eq!(off["saved_evidence"]["status"], "empty");
    assert!(fixture.ask("status")["payload"]["state"]["runtime"].is_null());
    assert_eq!(
        fixture.ask_input(
            "workspace",
            json!({"action":"history","scope_id":"ungranted"})
        )["code"],
        "native_context_assistance_disabled"
    );
    candidate(&fixture);
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    std::fs::write(
        root.join("README.md"),
        "Project history uses the original release procedure.\n",
    )
    .unwrap();
    let scope = data(fixture.ask_input(
        "workspace_grant",
        json!({"action":"grant","workspace":root,"app":"dashboard","sources":["README.md"]}),
    ));
    let id = &scope["scope_id"];
    let ask = |action, extra: serde_json::Value| {
        let mut request = json!({"action":action,"scope_id":id});
        request
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        fixture.ask_input("workspace", request)
    };
    let compiled = data(ask(
        "compile",
        json!({"query":"original release procedure"}),
    ));
    let history = data(ask("history", json!({})));
    assert_eq!(history["historical"], true);
    assert_eq!(history["current"], false);
    assert_eq!(history["entries"].as_array().unwrap().len(), 1);
    assert!(
        !history.to_string().contains("Project history uses"),
        "list metadata must omit brief text"
    );
    let original = &history["entries"][0]["history_id"];
    let detail = || data(ask("history_detail", json!({"history_id":original})));
    let first = detail();
    assert_eq!(first["source_states"][0]["state"], "unchanged");
    assert_eq!(
        first["brief"]["snapshot_id"],
        compiled["brief"]["snapshot_id"]
    );
    std::fs::write(
        root.join("README.md"),
        "Project history now uses a revised release procedure.\n",
    )
    .unwrap();
    let changed = detail();
    assert_eq!(changed["source_states"][0]["state"], "changed");
    assert!(changed["brief"]["rendered"]
        .as_str()
        .unwrap()
        .contains("original release procedure"));
    data(fixture.ask_input(
        "workspace_access",
        json!({"action":"refresh","scope_id":id}),
    ));
    let newer = data(ask("compile", json!({"query":"revised release procedure"})));
    assert_ne!(
        newer["brief"]["snapshot_id"],
        compiled["brief"]["snapshot_id"]
    );
    assert_eq!(
        data(ask("history", json!({})))["entries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        detail()["brief"]["snapshot_id"],
        compiled["brief"]["snapshot_id"]
    );
    // Unsafe current source access must never disclose retained text, even
    // though the earlier copy was admitted before the file became unsafe.
    std::fs::write(root.join("README.md"), "\0unsafe current source").unwrap();
    let unavailable = detail();
    assert_eq!(unavailable["source_access"], "unavailable");
    assert!(unavailable["brief"].is_null());
    std::fs::write(
        root.join("README.md"),
        "Project history now uses a revised release procedure.\n",
    )
    .unwrap();
    assert_eq!(
        fixture.ask_input("workspace", json!({"action":"forget_history"}))["code"],
        "native_context_assistance_workspace_input_invalid"
    );
    let forgotten = data(fixture.ask_input("workspace_access", json!({"action":"forget_history"})));
    assert_eq!(forgotten["history_entries"], 0);
    assert_eq!(forgotten["current_contexts"], 1);
    data(ask(
        "explain",
        json!({"snapshot_id":newer["brief"]["snapshot_id"]}),
    ));
    data(ask("compile", json!({"query":"revised release procedure"})));
    data(fixture.ask_input(
        "workspace_access",
        json!({"action":"withdraw","scope_id":id,"source_id":scope["sources"][0]["source_id"]}),
    ));
    assert_eq!(data(ask("history", json!({})))["entries"], json!([]));
    assert_eq!(
        ask("history_detail", json!({"history_id":original}))["code"],
        "native_context_assistance_context_stale"
    );
    data(fixture.ask_input("workspace_access", json!({"action":"clear"})));
    let empty = data(fixture.ask_input("workspace", json!({"action":"data"})));
    assert_eq!(empty["active_scopes"], 0);
    assert_eq!(empty["history_entries"], 0);
    fixture.ask("stop");
    assert_eq!(
        ask("history", json!({}))["code"],
        "native_context_assistance_disabled"
    );
    println!(
        "GUARD_CIGAR_HISTORY_VERIFICATION={}",
        json!({"schema":"guard-cigar-history-verification.v1","status":"passed",
        "qualification":"native-library-and-actual-sdk-only","history_observation":history,"detail_observation":first,
        "checks":["actual_sdk_brief_retained","metadata_omits_text_and_query","historical_not_current_or_execution",
            "changed_source_marked","refresh_preserves_historical_snapshot","unsafe_source_withholds_text","read_cannot_forget",
            "forget_preserves_current_context","withdraw_purges_history","clear_forgets_grants_and_history","off_refuses_history"]})
    );
}
