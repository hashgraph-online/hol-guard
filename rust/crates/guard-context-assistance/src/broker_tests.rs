use super::*;

fn document(id: &str, text: &str) -> ContextDocument {
    ContextDocument {
        id: id.into(),
        text: text.into(),
        start_line: 1,
    }
}
pub(super) fn shared_config() -> ContextAssistanceConfig {
    let mut config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "candidate".into(),
        ..Default::default()
    };
    config.features.agent_context = true;
    config.features.shared_agents = true;
    config
}

#[path = "broker_validation_tests.rs"]
mod validation;

#[test]
#[ignore = "requires explicitly selected approved final CPython 3.14 and actual CIGAR 0.14.1"]
fn actual_broker_independent_clients_scopes_proposals_conflicts_leases_and_recovery() {
    let selection: crate::RuntimeSelection = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit selection"))
            .unwrap(),
    )
    .unwrap();
    let approval: crate::BundleApproval = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit approval"))
            .unwrap(),
    )
    .unwrap();
    let mut runtime = VerifiedRuntime::start(selection, &approval).unwrap();
    let config = shared_config();
    let mut disabled = config.clone();
    disabled.features.shared_agents = false;
    assert!(matches!(
        runtime.open_broker_domain("broker:fixture", &disabled),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(runtime.brokers.domains.is_empty());
    let domain = runtime
        .open_broker_domain("broker:fixture", &config)
        .unwrap();
    let docs0 = runtime.broker_source_revision(&domain, "docs").unwrap();
    let docs1 = runtime
        .broker_replace_source(
            &domain,
            "docs",
            &docs0,
            vec![document(
                "readme",
                "Project deployment requires a reviewed release procedure.",
            )],
        )
        .unwrap();
    assert_eq!(docs1.version, "1");
    let private0 = runtime.broker_source_revision(&domain, "private").unwrap();
    runtime
        .broker_replace_source(
            &domain,
            "private",
            &private0,
            vec![document(
                "private-note",
                "Unrelated private project material.",
            )],
        )
        .unwrap();
    let notes0 = runtime
        .broker_source_revision(&domain, "guard:notes")
        .unwrap();
    let notes0 = runtime
        .broker_replace_source(&domain, "guard:notes", &notes0, vec![])
        .unwrap();
    let readable = BTreeSet::from(["docs".into(), "guard:notes".into()]);
    let writable = BTreeSet::from(["guard:notes".into()]);
    let deadline = Instant::now() + Duration::from_secs(300);
    let a = runtime
        .grant_broker_client_with_deadline(
            &domain,
            readable.clone(),
            writable.clone(),
            "policy:one",
            Duration::from_secs(300),
            Some(deadline),
        )
        .unwrap();
    assert_eq!(runtime.brokers.clients[&a.id].expires, deadline);
    let b = runtime
        .grant_broker_client(
            &domain,
            readable.clone(),
            writable.clone(),
            "policy:one",
            Duration::from_secs(300),
        )
        .unwrap();
    let read_only = runtime
        .grant_broker_client(
            &domain,
            BTreeSet::from(["docs".into()]),
            BTreeSet::new(),
            "policy:one",
            Duration::from_secs(300),
        )
        .unwrap();
    let pids = BTreeSet::from([
        runtime.brokers.clients[&a.id].process.pid(),
        runtime.brokers.clients[&b.id].process.pid(),
        runtime.brokers.clients[&read_only.id].process.pid(),
    ]);
    assert_eq!(pids.len(), 3);
    assert!(!pids.contains(&runtime.process.pid()));
    let notes_only = runtime
        .grant_broker_client(
            &domain,
            BTreeSet::from(["guard:notes".into()]),
            BTreeSet::new(),
            "policy:one",
            Duration::from_secs(300),
        )
        .unwrap();
    assert!(matches!(
        runtime.compile_broker_context(&a, "private", vec!["private-note".into()]),
        Err(RuntimeError::ScopeDenied)
    ));
    let first = runtime
        .compile_broker_context(&a, "release procedure", vec!["readme".into()])
        .unwrap();
    let second = runtime
        .compile_broker_context(&b, "release procedure", vec!["readme".into()])
        .unwrap();
    assert!(first
        .brief()
        .rendered
        .contains("reviewed release procedure"));
    let encoded = serde_json::to_string(first.brief()).unwrap();
    assert!(
        !encoded.contains("ticket")
            && !encoded.contains("secret")
            && !encoded.contains("Unrelated private")
    );
    runtime.explain_broker_context(&first).unwrap();
    let foreign = RetainedBrokerContext {
        client: b.clone(),
        retention_id: first.retention_id,
        brief: first.brief.clone(),
    };
    assert!(matches!(
        runtime.explain_broker_context(&foreign),
        Err(RuntimeError::ContextStale)
    ));
    let read_context = runtime
        .compile_broker_context(&read_only, "release procedure", vec!["readme".into()])
        .unwrap();
    assert!(matches!(
        runtime.propose_broker_evidence(
            &read_context,
            "readonly",
            notes0.clone(),
            vec![document("note:read", "Must remain a proposal.")]
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    let pa = runtime
        .propose_broker_evidence(
            &first,
            "a:one",
            notes0.clone(),
            vec![document(
                "note:a",
                "Reviewed team guidance requires the deployment checklist.",
            )],
        )
        .unwrap();
    let repeated = runtime
        .propose_broker_evidence(
            &first,
            "a:one",
            notes0.clone(),
            vec![document(
                "note:a",
                "Reviewed team guidance requires the deployment checklist.",
            )],
        )
        .unwrap();
    assert_eq!(pa, repeated);
    assert!(matches!(
        runtime.propose_broker_evidence(
            &first,
            "a:one",
            notes0.clone(),
            vec![document("note:a", "Changed proposal content.")]
        ),
        Err(RuntimeError::ContextConflict)
    ));
    let pb = runtime
        .propose_broker_evidence(
            &second,
            "b:one",
            notes0.clone(),
            vec![document(
                "note:b",
                "Competing team guidance uses a different checklist.",
            )],
        )
        .unwrap();
    assert!(matches!(
        runtime.compile_broker_context(&a, "checklist", vec!["note:a".into()]),
        Err(RuntimeError::ScopeDenied)
    ));
    let pending = runtime.list_broker_proposals(&domain).unwrap();
    assert_eq!(pending.len(), 2);
    let aid = pa["proposal_id"].as_str().unwrap();
    let bid = pb["proposal_id"].as_str().unwrap();
    let inspected = runtime.inspect_broker_proposal(&domain, aid).unwrap();
    assert_eq!(inspected.basis["docs"], docs1);
    let admitted = runtime.admit_broker_proposal(&domain, aid).unwrap();
    assert_eq!(
        admitted.version,
        (notes0.version.parse::<u64>().unwrap() + 1).to_string()
    );
    assert!(matches!(
        runtime.admit_broker_proposal(&domain, bid),
        Err(RuntimeError::ContextConflict)
    ));
    assert!(runtime.status().active);
    assert!(matches!(
        runtime.compile_broker_context(&notes_only, "checklist", vec!["note:a".into()]),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(matches!(
        runtime.grant_broker_client(
            &domain,
            BTreeSet::from(["guard:notes".into()]),
            BTreeSet::new(),
            "policy:one",
            Duration::from_secs(300)
        ),
        Err(RuntimeError::ScopeDenied)
    ));
    runtime.reject_broker_proposal(&domain, bid).unwrap();
    assert_eq!(
        runtime.broker_proposal_status(&a, "a:one").unwrap()["outcome"]["status"],
        "admitted"
    );
    assert_eq!(
        runtime.broker_proposal_status(&b, "b:one").unwrap()["outcome"]["status"],
        "rejected"
    );
    assert!(matches!(
        runtime.broker_proposal_status(&b, "a:one"),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(matches!(
        runtime.explain_broker_context(&first),
        Err(RuntimeError::ContextStale)
    ));
    let shared = runtime
        .compile_broker_context(&b, "deployment checklist", vec!["note:a".into()])
        .unwrap();
    assert!(shared.brief().rendered.contains("Reviewed team guidance"));
    assert!(shared
        .brief()
        .citations
        .iter()
        .any(|c| c["source"] == "guard:notes"));
    assert_eq!(
        runtime.broker_context_sources(&shared).unwrap()["docs"],
        docs1
    );
    let inherited = runtime
        .propose_broker_evidence(
            &shared,
            "b:inherited",
            admitted.clone(),
            vec![document(
                "note:inherited",
                "New notes preserve their upstream evidence dependencies.",
            )],
        )
        .unwrap();
    let inherited_id = inherited["proposal_id"].as_str().unwrap();
    assert_eq!(
        runtime
            .inspect_broker_proposal(&domain, inherited_id)
            .unwrap()
            .basis["docs"],
        docs1
    );
    runtime
        .reject_broker_proposal(&domain, inherited_id)
        .unwrap();
    runtime.forget_broker_proposal(&a, "a:one").unwrap();
    assert!(matches!(
        runtime.broker_proposal_status(&a, "a:one"),
        Err(RuntimeError::ScopeDenied)
    ));
    let current = runtime
        .compile_broker_context(&a, "release procedure", vec!["readme".into()])
        .unwrap();
    for index in 0..4 {
        runtime
            .propose_broker_evidence(
                &current,
                &format!("quota:{index}"),
                admitted.clone(),
                vec![document(
                    &format!("note:quota{index}"),
                    "Review this bounded team note.",
                )],
            )
            .unwrap();
    }
    assert!(matches!(
        runtime.propose_broker_evidence(
            &current,
            "quota:excess",
            admitted.clone(),
            vec![document("note:excess", "Must remain bounded.")]
        ),
        Err(RuntimeError::ResourceLimit)
    ));
    runtime.forget_broker_proposal(&a, "quota:0").unwrap();
    runtime
        .propose_broker_evidence(
            &current,
            "quota:excess",
            admitted.clone(),
            vec![document(
                "note:excess",
                "A freed slot can be used explicitly.",
            )],
        )
        .unwrap();
    for proposal in runtime.list_broker_proposals(&domain).unwrap() {
        runtime
            .reject_broker_proposal(&domain, &proposal.proposal_id)
            .unwrap();
        runtime
            .forget_broker_proposal(&a, &proposal.request_key)
            .unwrap();
    }
    let stale_proposal = runtime
        .propose_broker_evidence(
            &current,
            "stale:basis",
            admitted.clone(),
            vec![document(
                "note:stale",
                "Do not admit against a changed upstream revision.",
            )],
        )
        .unwrap();
    let docs2 = runtime
        .broker_replace_source(
            &domain,
            "docs",
            &docs1,
            vec![document(
                "readme",
                "Project deployment now requires a revised release procedure.",
            )],
        )
        .unwrap();
    assert_eq!(docs2.version, "2");
    assert!(matches!(
        runtime.admit_broker_proposal(&domain, stale_proposal["proposal_id"].as_str().unwrap()),
        Err(RuntimeError::ContextStale)
    ));
    runtime
        .reject_broker_proposal(&domain, stale_proposal["proposal_id"].as_str().unwrap())
        .unwrap();
    assert!(matches!(
        runtime.explain_broker_context(&shared),
        Err(RuntimeError::ContextStale)
    ));
    assert!(matches!(
        runtime.compile_broker_context(&b, "checklist", vec!["note:a".into()]),
        Err(RuntimeError::ContextStale)
    ));
    runtime.revoke_broker_client(&a).unwrap();
    assert!(matches!(
        runtime.compile_broker_context(&a, "release", vec![]),
        Err(RuntimeError::ScopeDenied)
    ));
    let fresh = runtime
        .compile_broker_context(
            &read_only,
            "revised release procedure",
            vec!["readme".into()],
        )
        .unwrap();
    assert!(fresh.brief().rendered.contains("revised release procedure"));
    for _ in 0..12 {
        runtime
            .compile_broker_context(
                &read_only,
                "revised release procedure",
                vec!["readme".into()],
            )
            .unwrap();
    }
    assert_eq!(runtime.brokers.clients[&read_only.id].contexts.len(), 8);
    assert!(matches!(
        runtime.explain_broker_context(&fresh),
        Err(RuntimeError::ContextStale)
    ));
    let short = runtime
        .grant_broker_client(
            &domain,
            BTreeSet::from(["docs".into()]),
            BTreeSet::new(),
            "policy:one",
            Duration::from_millis(3000),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(3100));
    assert!(matches!(
        runtime.compile_broker_context(&short, "release", vec![]),
        Err(RuntimeError::ScopeDenied)
    ));
    runtime.close_broker_domain(&domain).unwrap();
    let replacement = runtime
        .open_broker_domain("broker:fixture", &config)
        .unwrap();
    assert_ne!(replacement.domain_epoch, domain.domain_epoch);
    assert!(matches!(
        runtime.close_broker_domain(&domain),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(matches!(
        runtime.broker_source_revision(&domain, "docs"),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(matches!(
        runtime.compile_broker_context(&b, "release", vec![]),
        Err(RuntimeError::ScopeDenied)
    ));
    let empty = runtime
        .broker_source_revision(&replacement, "docs")
        .unwrap();
    runtime
        .broker_replace_source(
            &replacement,
            "docs",
            &empty,
            vec![document("readme", "Fresh authority owns new evidence.")],
        )
        .unwrap();
    let live = runtime
        .grant_broker_client(
            &replacement,
            BTreeSet::from(["docs".into()]),
            BTreeSet::new(),
            "policy:two",
            Duration::from_secs(300),
        )
        .unwrap();
    runtime
        .compile_broker_context(&live, "fresh evidence", vec!["readme".into()])
        .unwrap();
    let start = Instant::now();
    runtime.close();
    let stop_ms = start.elapsed().as_millis();
    assert!(stop_ms < 500);
    assert!(runtime.brokers.clients.is_empty() && runtime.brokers.domains.is_empty());
    println!(
        "GUARD_CIGAR_BROKER_VERIFICATION={}",
        json!({"schema":"guard-cigar-broker-native-verification.v1","status":"passed",
        "qualification":"native_library_actual_sdk_and_independent_clients","independent_client_processes":3,"stop_ms":stop_ms,
        "worker_fingerprint":approval.worker_sha256,"package_fingerprint":approval.package_tree_sha256,
        "checks":["explicit_sharing_gate","protected_client_grant_delivery","independent_cpython_clients","foreign_source_refused","foreign_context_refused","read_only_cannot_propose","idempotent_proposal_key_and_changed_payload_conflict","quarantine_before_admission","host_inspection","host_admission_with_basis_dependencies","competing_source_cas_conflict","known_conflict_preserves_runtime","cross_client_status_refused","per_client_proposal_quota_and_explicit_forgetting","changed_basis_refuses_pending_admission","repeated_snapshot_tickets_remain_bounded","revoke_and_finite_lease","changed_upstream_invalidates_admitted_note","new_epoch_cannot_revive_old_handles","shutdown_reaps_live_client_and_host"]})
    );
}
