use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State,
    ProviderEffectLevelV1 as Level, ProviderInventoryV1, ProviderSignalStateV1, ProviderSignalV1,
    ProviderSubjectKindV1, ProviderSubjectV1, ProviderVerdictV1 as Verdict,
    PROVIDER_CAUTION_REVIEWS_PER_SESSION, PROVIDER_SIGNAL_V1_VERSION,
};
use guard_provider_integrations::noise::BaselineDecision::{Allow, Block, Review};

use super::*;
use crate::provider_integration_store::{
    ensure_provider_integration_schema, put_capability_setting, put_connection, put_signal,
    set_connection_state, ProviderConnection,
};

const SHIELD: &str = "provider.exampleshield";
const OTHER: &str = "provider.otherwatch";
const THIRD: &str = "provider.fixture-third";
const NOW: u64 = 10_000_000;

fn digest(n: u64) -> String {
    format!("{n:064x}")
}

fn store(providers: &[&str]) -> Connection {
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    for provider_id in providers {
        put_connection(
            &connection,
            &ProviderConnection {
                provider_id: (*provider_id).to_owned(),
                manifest_digest: digest(7),
                state: State::Connected,
                opt_in_facts: Vec::new(),
                connected_at_ms: 1_000,
                updated_at_ms: 1_000,
                last_verified_at_ms: Some(1_000),
            },
        )
        .unwrap();
    }
    connection
}

fn cache(connection: &Connection, provider_id: &str, subject: u64, verdict: Verdict, ttl_ms: u64) {
    put_signal(
        connection,
        &ProviderSignalV1 {
            version: PROVIDER_SIGNAL_V1_VERSION,
            provider_id: provider_id.to_owned(),
            capability: Cap::OriginReputation,
            subject: ProviderSubjectV1 {
                kind: ProviderSubjectKindV1::Origin,
                digest: digest(subject),
            },
            verdict,
            reason_codes: vec!["phishing".to_owned()],
            observed_at_ms: NOW - 1_000,
            expires_at_ms: NOW - 1_000 + ttl_ms,
            inventory: ProviderInventoryV1::None,
            state: ProviderSignalStateV1::Fresh,
        },
    )
    .unwrap();
}

fn set(connection: &Connection, provider_id: &str, effect_level: Level, require_fresh: bool) {
    put_capability_setting(
        connection,
        provider_id,
        Cap::OriginReputation,
        CapabilitySetting {
            effect_level,
            require_fresh,
        },
    )
    .unwrap();
}

fn verified(provider_id: &str) -> DecideProvider<'_> {
    DecideProvider {
        provider_id,
        verified: true,
    }
}

fn unverified(provider_id: &str) -> DecideProvider<'_> {
    DecideProvider {
        provider_id,
        verified: false,
    }
}

fn run(
    connection: &Connection,
    ledger: &mut NoiseLedger,
    baseline: BaselineDecision,
    subject: u64,
    providers: &[DecideProvider<'_>],
) -> ProviderDecision {
    let digest = digest(subject);
    decide(
        connection,
        ledger,
        &DecideRequest {
            baseline,
            capability: Cap::OriginReputation,
            subject_digest: &digest,
            providers,
            now_ms: NOW,
        },
    )
    .unwrap()
}

#[test]
fn no_provider_leaves_the_decision_alone() {
    let connection = store(&[]);
    for baseline in [Allow, Review, Block] {
        let decided = run(&connection, &mut NoiseLedger::new(), baseline, 1, &[]);
        assert_eq!(decided, ProviderDecision::unchanged(baseline));
    }
}

#[test]
fn ok_is_a_finding_and_never_lowers_a_review() {
    let connection = store(&[SHIELD]);
    cache(&connection, SHIELD, 1, Verdict::Ok, 60_000);
    let mut ledger = NoiseLedger::new();
    let decided = run(&connection, &mut ledger, Allow, 1, &[verified(SHIELD)]);
    assert_eq!(decided.decision, Allow);
    assert_eq!(decided.effect, ProviderEffect::Finding);
    assert_eq!(decided.deciding_provider.as_deref(), Some(SHIELD));
    let decided = run(&connection, &mut ledger, Review, 1, &[verified(SHIELD)]);
    assert_eq!(decided.decision, Review);
    let decided = run(&connection, &mut ledger, Block, 1, &[verified(SHIELD)]);
    assert_eq!(decided.decision, Block);
}

#[test]
fn verified_caution_reviews_once_and_unverified_caution_is_a_finding() {
    let connection = store(&[SHIELD, OTHER]);
    cache(&connection, SHIELD, 1, Verdict::Caution, 60_000);
    cache(&connection, OTHER, 2, Verdict::Caution, 60_000);
    let mut ledger = NoiseLedger::new();
    let first = run(&connection, &mut ledger, Allow, 1, &[verified(SHIELD)]);
    assert_eq!(first.decision, Review);
    assert_eq!(first.effect, ProviderEffect::Review);
    assert!(!first.suspend_grants);
    let again = run(&connection, &mut ledger, Allow, 1, &[verified(SHIELD)]);
    assert_eq!(again.decision, Allow);
    assert_eq!(again.effect, ProviderEffect::Finding);

    let other = run(&connection, &mut ledger, Allow, 2, &[unverified(OTHER)]);
    assert_eq!(other.decision, Allow);
    assert_eq!(other.effect, ProviderEffect::Finding);
}

#[test]
fn danger_reviews_suspends_grants_and_blocks_only_under_enforce() {
    let connection = store(&[SHIELD]);
    cache(&connection, SHIELD, 1, Verdict::Danger, 60_000);
    let mut ledger = NoiseLedger::new();
    let tighten = run(&connection, &mut ledger, Allow, 1, &[unverified(SHIELD)]);
    assert_eq!(tighten.decision, Review);
    assert!(tighten.suspend_grants);
    let again = run(&connection, &mut ledger, Allow, 1, &[unverified(SHIELD)]);
    assert_eq!(again.decision, Review, "danger is never capped");

    set(&connection, SHIELD, Level::Enforce, false);
    let enforce = run(&connection, &mut ledger, Review, 1, &[unverified(SHIELD)]);
    assert_eq!(enforce.decision, Block);
    assert!(enforce.suspend_grants);

    set(&connection, SHIELD, Level::Observe, false);
    let observe = run(&connection, &mut ledger, Allow, 1, &[unverified(SHIELD)]);
    assert_eq!(observe.decision, Allow);
    assert_eq!(observe.effect, ProviderEffect::WouldHaveReviewed);
    assert!(!observe.suspend_grants);
}

#[test]
fn an_ok_from_one_provider_does_not_cancel_danger_from_another() {
    let connection = store(&[SHIELD, OTHER]);
    cache(&connection, SHIELD, 1, Verdict::Ok, 60_000);
    cache(&connection, OTHER, 1, Verdict::Danger, 60_000);
    let decided = run(
        &connection,
        &mut NoiseLedger::new(),
        Allow,
        1,
        &[verified(SHIELD), unverified(OTHER)],
    );
    assert_eq!(decided.decision, Review);
    assert_eq!(decided.deciding_provider.as_deref(), Some(OTHER));
    let order: Vec<&str> = decided
        .answers
        .iter()
        .map(|answer| answer.provider_id.as_str())
        .collect();
    assert_eq!(order, vec![OTHER, SHIELD]);
    assert_eq!(decided.answers[0].reason_codes, vec!["phishing".to_owned()]);
}

#[test]
fn an_expired_answer_or_a_lost_connection_has_no_effect_and_is_unavailable() {
    let connection = store(&[SHIELD, OTHER]);
    cache(&connection, SHIELD, 1, Verdict::Danger, 500);
    cache(&connection, OTHER, 1, Verdict::Danger, 60_000);
    set_connection_state(&connection, OTHER, State::KeyInvalid, NOW).unwrap();
    let decided = run(
        &connection,
        &mut NoiseLedger::new(),
        Allow,
        1,
        &[verified(SHIELD), verified(OTHER)],
    );
    assert_eq!(decided.decision, Allow);
    assert_eq!(decided.effect, ProviderEffect::None);
    assert!(!decided.suspend_grants);
    assert_eq!(decided.deciding_provider, None);
    assert_eq!(
        decided.unavailable,
        vec![SHIELD.to_owned(), OTHER.to_owned()]
    );
    assert!(decided.answers.iter().all(|answer| !answer.fresh));
}

#[test]
fn a_provider_not_asked_about_is_ignored() {
    let connection = store(&[SHIELD, OTHER]);
    cache(&connection, OTHER, 1, Verdict::Danger, 60_000);
    let decided = run(
        &connection,
        &mut NoiseLedger::new(),
        Allow,
        1,
        &[verified(SHIELD)],
    );
    assert_eq!(decided.decision, Allow);
    assert!(decided.answers.is_empty());
    assert_eq!(decided.unavailable, vec![SHIELD.to_owned()]);
}

#[test]
fn require_fresh_reviews_when_no_fresh_answer_is_cached() {
    let connection = store(&[SHIELD]);
    set(&connection, SHIELD, Level::Tighten, true);
    let mut ledger = NoiseLedger::new();
    let decided = run(&connection, &mut ledger, Allow, 1, &[verified(SHIELD)]);
    assert_eq!(decided.decision, Review);
    assert_eq!(decided.fresh_check_required, vec![SHIELD.to_owned()]);

    cache(&connection, SHIELD, 1, Verdict::Ok, 60_000);
    let decided = run(&connection, &mut ledger, Allow, 1, &[verified(SHIELD)]);
    assert_eq!(decided.decision, Allow);
    assert!(decided.fresh_check_required.is_empty());
}

#[test]
fn a_caution_that_joins_a_fresh_check_review_is_not_counted() {
    let connection = store(&[SHIELD, OTHER]);
    cache(&connection, SHIELD, 1, Verdict::Caution, 60_000);
    set(&connection, OTHER, Level::Tighten, true);
    let mut ledger = NoiseLedger::new();
    let decided = run(
        &connection,
        &mut ledger,
        Allow,
        1,
        &[verified(SHIELD), verified(OTHER)],
    );
    assert_eq!(decided.decision, Review);
    assert_eq!(decided.effect, ProviderEffect::RidesOnGuardReview);
    assert_eq!(decided.fresh_check_required, vec![OTHER.to_owned()]);
    assert_eq!(ledger.caution_reviews(SHIELD), 0);
}

#[test]
fn several_cautions_about_one_subject_raise_one_review() {
    let connection = store(&[SHIELD, OTHER]);
    cache(&connection, SHIELD, 1, Verdict::Caution, 60_000);
    cache(&connection, OTHER, 1, Verdict::Caution, 60_000);
    let mut ledger = NoiseLedger::new();
    let providers = [verified(SHIELD), verified(OTHER)];
    assert_eq!(
        run(&connection, &mut ledger, Allow, 1, &providers).decision,
        Review
    );
    assert_eq!(
        run(&connection, &mut ledger, Allow, 1, &providers).decision,
        Allow
    );
    assert_eq!(
        ledger.caution_reviews(SHIELD) + ledger.caution_reviews(OTHER),
        1
    );
}

/// A small deterministic generator so the property runs without an extra dependency.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[(self.next() % items.len() as u64) as usize]
    }

    fn chance(&mut self) -> bool {
        self.next() % 2 == 0
    }
}

#[test]
fn for_any_signal_set_the_decision_is_never_weaker_than_with_no_provider() {
    let ids = [SHIELD, OTHER, THIRD];
    let verdicts = [
        Verdict::Ok,
        Verdict::Caution,
        Verdict::Danger,
        Verdict::Unknown,
    ];
    let levels = [Level::Observe, Level::Tighten, Level::Enforce];
    let states = [State::Connected, State::Connected, State::KeyInvalid];
    let baselines = [Allow, Review, Block];
    let mut random = XorShift(0x9e37_79b9_7f4a_7c15);
    for round in 0..300 {
        let connection = store(&ids);
        let mut providers = Vec::new();
        for id in ids {
            if random.chance() {
                cache(
                    &connection,
                    id,
                    random.next() % 4,
                    random.pick(&verdicts),
                    random.pick(&[500, 60_000]),
                );
            }
            set(
                &connection,
                id,
                random.pick(&levels),
                random.next() % 4 == 0,
            );
            let state = random.pick(&states);
            if state != State::Connected {
                set_connection_state(&connection, id, state, NOW).unwrap();
            }
            if random.chance() {
                providers.push(DecideProvider {
                    provider_id: id,
                    verified: random.chance(),
                });
            }
        }
        let mut ledger = NoiseLedger::new();
        for step in 0..20 {
            let baseline = random.pick(&baselines);
            let subject = random.next() % 4;
            let alone = run(&connection, &mut NoiseLedger::new(), baseline, subject, &[]);
            let decided = run(&connection, &mut ledger, baseline, subject, &providers);
            assert!(
                decided.decision >= alone.decision,
                "round {round} step {step}: {decided:?} weaker than {alone:?}"
            );
            assert_eq!(alone.decision, baseline);
            if decided.decision == Block && baseline != Block {
                assert_eq!(decided.effect, ProviderEffect::Block, "round {round}");
            }
            if decided.decision > baseline {
                assert!(
                    matches!(
                        decided.effect,
                        ProviderEffect::Review | ProviderEffect::Block
                    ) || !decided.fresh_check_required.is_empty(),
                    "round {round} step {step}: {decided:?}"
                );
            }
            for id in ids {
                assert!(
                    ledger.caution_reviews(id) <= PROVIDER_CAUTION_REVIEWS_PER_SESSION,
                    "round {round}"
                );
            }
        }
    }
}
