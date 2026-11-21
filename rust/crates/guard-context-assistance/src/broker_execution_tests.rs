use super::*;

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
