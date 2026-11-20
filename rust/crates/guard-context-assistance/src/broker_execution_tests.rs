use super::*;

fn host_review(submission: &BrokerSubmission) -> BrokerExecutionReview {
    BrokerExecutionReview {
        authority_revision: "native-review:one".into(),
        reviews: submission
            .review_keys()
            .iter()
            .map(|key| BrokerClaimReview {
                claim_key: key.clone(),
                verdict: BrokerReviewVerdict::Supported,
                reviewed_counterevidence: vec![],
            })
            .collect(),
        policy: BrokerAnswerPolicy::default(),
    }
}
fn draft() -> Vec<BrokerAnswerClaim> {
    vec![BrokerAnswerClaim {
        text: "Native captured action observation is data; Guard retains execution authority."
            .into(),
        citations: vec!["native-observation".into()],
        confidence_bps: Some(10_000),
    }]
}
fn context(runtime: &mut VerifiedRuntime, client: &BrokerClientHandle) -> RetainedBrokerContext {
    runtime
        .compile_broker_context(
            client,
            "native captured action",
            vec!["native-observation".into()],
        )
        .unwrap()
}
fn bind(
    runtime: &mut VerifiedRuntime,
    context: &RetainedBrokerContext,
    effect: &str,
) -> (BrokerBoundExecution, BrokerExecutionReview) {
    let submission = runtime.submit_broker_answer(context, draft()).unwrap();
    let review = host_review(&submission);
    let bound = runtime
        .bind_broker_execution(
            context,
            &submission,
            effect,
            &format!("1220{}", "c".repeat(64)),
            &review,
        )
        .unwrap();
    (bound, review)
}

#[test]
fn host_review_requires_bounded_policy_and_unique_exact_claim_keys() {
    assert!(intent(&format!("1220{}", "a".repeat(64))));
    assert!(!intent(&format!("1220{}", "A".repeat(64))));
    assert!(!intent(&"a".repeat(64)));
    let mut value = BrokerExecutionReview {
        authority_revision: "native:one".into(),
        reviews: vec![],
        policy: BrokerAnswerPolicy::default(),
    };
    review(&value).unwrap();
    value.policy.min_sources = Some(0);
    assert_eq!(review(&value), Err(RuntimeError::RequestInvalid));
    value.policy.min_sources = Some(1);
    value.reviews = vec![
        BrokerClaimReview {
            claim_key: "a".repeat(64),
            verdict: BrokerReviewVerdict::Supported,
            reviewed_counterevidence: vec![]
        };
        2
    ];
    assert_eq!(review(&value), Err(RuntimeError::RequestInvalid));
}

#[test]
#[ignore = "requires the explicitly approved actual CPython 3.14/CIGAR 0.14.1 candidate"]
fn actual_sdk_execution_precondition_requires_current_host_review_and_consumes_once() {
    let selection = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit selection"))
            .unwrap(),
    )
    .unwrap();
    let approval = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit approval"))
            .unwrap(),
    )
    .unwrap();
    let mut runtime = VerifiedRuntime::start(selection, &approval).unwrap();
    let config = super::super::tests::shared_config();
    let domain = runtime
        .open_broker_domain("execution:fixture", &config)
        .unwrap();
    assert!(runtime.brokers.domains[&domain.id].execution_handoff);
    let revision = runtime
        .broker_source_revision(&domain, "guard:action")
        .unwrap();
    runtime
        .broker_replace_source(
            &domain,
            "guard:action",
            &revision,
            vec![ContextDocument {
                id: "native-observation".into(),
                start_line: 1,
                text: draft()[0].text.clone(),
            }],
        )
        .unwrap();
    let client = runtime
        .grant_broker_client(
            &domain,
            BTreeSet::from(["guard:action".into()]),
            BTreeSet::new(),
            "native-policy:one",
            Duration::from_secs(300),
        )
        .unwrap();

    let ctx = context(&mut runtime, &client);
    let mut foreign = draft();
    foreign[0].citations = vec!["unselected".into()];
    assert_eq!(
        runtime.submit_broker_answer(&ctx, foreign).err(),
        Some(RuntimeError::RequestInvalid)
    );
    runtime
        .brokers
        .domains
        .get_mut(&domain.id)
        .unwrap()
        .execution_handoff = false;
    assert_eq!(
        runtime.submit_broker_answer(&ctx, draft()).err(),
        Some(RuntimeError::HandshakeFailed)
    );
    runtime
        .brokers
        .domains
        .get_mut(&domain.id)
        .unwrap()
        .execution_handoff = true;
    let submission = runtime.submit_broker_answer(&ctx, draft()).unwrap();
    let trusted = host_review(&submission);
    let mut unreviewed = trusted.clone();
    unreviewed.reviews.clear();
    let intent = format!("1220{}", "c".repeat(64));
    assert_eq!(
        runtime
            .bind_broker_execution(&ctx, &submission, "effect:one", &intent, &unreviewed)
            .err(),
        Some(RuntimeError::ScopeDenied)
    );
    assert!(
        runtime.status().active,
        "known review refusal does not poison the runtime"
    );
    let binding = runtime
        .bind_broker_execution(&ctx, &submission, "effect:one", &intent, &trusted)
        .unwrap();
    assert_eq!(
        runtime
            .bind_broker_execution(&ctx, &submission, "effect:one", &intent, &trusted)
            .err(),
        Some(RuntimeError::ContextConflict)
    );
    let replay = BrokerBoundExecution {
        client: binding.client.clone(),
        retention_id: binding.retention_id,
        wire: serde_json::from_value(serde_json::to_value(&binding.wire).unwrap()).unwrap(),
        draft_id: binding.draft_id.clone(),
    };
    let receipt = runtime
        .take_broker_execution(&ctx, binding, &trusted)
        .unwrap();
    assert_eq!(receipt.effect_id(), "effect:one");
    assert_eq!(receipt.intent_digest(), intent);
    let metadata = receipt.metadata();
    assert_eq!(metadata["approval_grant"], false);
    assert_eq!(metadata["dispatch_confirmed"], false);
    for omitted in ["ticket", "secret", "submission_id", "intent_digest"] {
        assert!(!metadata.to_string().contains(omitted));
    }
    assert_eq!(
        runtime.take_broker_execution(&ctx, replay, &trusted).err(),
        Some(RuntimeError::ContextConflict)
    );

    let ctx = context(&mut runtime, &client);
    let (binding, trusted) = bind(&mut runtime, &ctx, "effect:review");
    let mut changed = trusted.clone();
    changed.authority_revision = "native-review:two".into();
    assert_eq!(
        runtime.take_broker_execution(&ctx, binding, &changed).err(),
        Some(RuntimeError::ContextStale)
    );
    assert!(runtime.status().active);
    let ctx = context(&mut runtime, &client);
    let (binding, mut changed) = bind(&mut runtime, &ctx, "effect:policy");
    changed.policy.min_sources = Some(2);
    assert_eq!(
        runtime.take_broker_execution(&ctx, binding, &changed).err(),
        Some(RuntimeError::ContextStale)
    );

    let ctx = context(&mut runtime, &client);
    let (binding, trusted) = bind(&mut runtime, &ctx, "effect:submission");
    runtime.submit_broker_answer(&ctx, draft()).unwrap();
    assert_eq!(
        runtime.take_broker_execution(&ctx, binding, &trusted).err(),
        Some(RuntimeError::ContextStale)
    );

    let ctx = context(&mut runtime, &client);
    let (binding, trusted) = bind(&mut runtime, &ctx, "effect:lost-reply");
    // Actual SDK consumption at a named boundary; deliberately discard its
    // reply to model loss before the caller observes it. Only this test can
    // export private bytes. The public Rust handle cannot be cloned/retried.
    runtime
        .rpc(
            json!({"op":"broker_take_execution","domain":domain.id,
        "binding":binding.wire,"review":trusted}),
            TIMEOUT,
        )
        .unwrap();
    assert_eq!(
        runtime.take_broker_execution(&ctx, binding, &trusted).err(),
        Some(RuntimeError::ContextConflict)
    );

    let ctx = context(&mut runtime, &client);
    let (binding, trusted) = bind(&mut runtime, &ctx, "effect:source");
    let current = runtime
        .broker_source_revision(&domain, "guard:action")
        .unwrap();
    runtime
        .broker_replace_source(
            &domain,
            "guard:action",
            &current,
            vec![ContextDocument {
                id: "native-observation".into(),
                start_line: 1,
                text: draft()[0].text.clone() + " New native revision.",
            }],
        )
        .unwrap();
    assert_eq!(
        runtime.take_broker_execution(&ctx, binding, &trusted).err(),
        Some(RuntimeError::ContextStale)
    );

    let ctx = context(&mut runtime, &client);
    let (binding, trusted) = bind(&mut runtime, &ctx, "effect:revoke");
    runtime.revoke_broker_client(&client).unwrap();
    assert_eq!(
        runtime.take_broker_execution(&ctx, binding, &trusted).err(),
        Some(RuntimeError::ScopeDenied)
    );
    runtime.close_broker_domain(&domain).unwrap();
    runtime.close();
    println!("GUARD_CIGAR_NATIVE_EXECUTION_PRECONDITION sdk_consumes_once=true trusted_review_required=true changed_review_policy_source_submission_refused=true revoked_refused=true lost_reply_not_repeatable=true actual_executor_qualified=false");
}
