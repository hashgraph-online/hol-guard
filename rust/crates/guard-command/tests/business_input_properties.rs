//! Seeded generated-input checks for the owned business input commitment.

#[path = "support/business_properties.rs"]
mod business_properties;

use business_properties::{Rng, CASES};
use guard_command::business_input::{
    business_input_snapshot_digest, PreparedBusinessInputErrorV1, PreparedBusinessInputV1,
};
use guard_contracts::{MAX_BUSINESS_ACTION_ITEMS, MAX_BUSINESS_INLINE_BYTES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Top-level fields of complete synthetic facts committing to these bytes.
fn facts_fields(primary: &[u8], attachments: &[Vec<u8>]) -> Vec<(&'static str, Value)> {
    let total = primary.len() + attachments.iter().map(Vec::len).sum::<usize>();
    vec![
        ("schema", json!("guard.business-action.v1")),
        ("version", json!(1)),
        (
            "provider",
            json!({
                "service": "google_gmail", "identity_state": "known",
                "account_binding": "a".repeat(64), "tenant_binding": "b".repeat(64),
                "tool_identity_digest": "c".repeat(64), "tool_schema_digest": "d".repeat(64)
            }),
        ),
        ("operation", json!("mail_send")),
        (
            "audience",
            json!({"kind": "named", "expansion_state": "known", "recipients": [
                {"identity_binding": "e".repeat(64), "domain": "example.test", "kind": "to"}
            ]}),
        ),
        (
            "content",
            json!({
                "snapshot_digest": business_input_snapshot_digest(primary, attachments).unwrap(),
                "attachment_digests": attachments.iter().map(|bytes| sha256_hex(bytes)).collect::<Vec<_>>(),
                "inspection_state": "known", "inspected_bytes": total,
                "sensitivity_labels": ["confidential"]
            }),
        ),
        (
            "target",
            json!({
                "resource_binding": "1".repeat(64), "revision_binding": "2".repeat(64),
                "field_diff_digest": "3".repeat(64), "batch_manifest_digest": "4".repeat(64)
            }),
        ),
        (
            "volume",
            json!({"recipient_count": 1, "record_count": 1, "byte_count": total}),
        ),
        ("completeness", json!("known")),
    ]
}

fn facts_json(fields: &[(&str, Value)], order: &[usize]) -> Vec<u8> {
    let members: Vec<String> = order
        .iter()
        .map(|&index| format!("{}:{}", json!(fields[index].0), fields[index].1))
        .collect();
    format!("{{{}}}", members.join(",")).into_bytes()
}

fn generated_input(rng: &mut Rng) -> (Vec<u8>, Vec<Vec<u8>>) {
    let primary = rng.bytes(256);
    let attachments = (0..rng.below(5)).map(|_| rng.bytes(64)).collect();
    (primary, attachments)
}

#[test]
fn prepared_input_keeps_exact_bytes_and_a_key_order_independent_binding() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(17, case);
        let (primary, attachments) = generated_input(&mut rng);
        let fields = facts_fields(&primary, &attachments);
        let natural: Vec<usize> = (0..fields.len()).collect();
        let mut shuffled = natural.clone();
        for index in (1..shuffled.len()).rev() {
            shuffled.swap(index, rng.below(index + 1));
        }
        let first = PreparedBusinessInputV1::prepare(
            &facts_json(&fields, &natural),
            primary.clone(),
            attachments.clone(),
        )
        .unwrap_or_else(|error| panic!("case {case}: {error:?}"));
        assert_eq!(first.primary_bytes(), primary, "case {case}");
        assert!(first
            .attachments()
            .eq(attachments.iter().map(Vec::as_slice)));
        let second = PreparedBusinessInputV1::prepare(
            &facts_json(&fields, &shuffled),
            primary.clone(),
            attachments.clone(),
        )
        .unwrap();
        assert_eq!(first.binding(), second.binding(), "case {case}");
    }
}

#[test]
fn altered_bytes_or_partitions_never_match_committed_facts() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(18, case);
        let (primary, attachments) = generated_input(&mut rng);
        let fields = facts_fields(&primary, &attachments);
        let facts = facts_json(&fields, &(0..fields.len()).collect::<Vec<_>>());
        let mut variants: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();

        let mut flipped = primary.clone();
        let at = rng.below(flipped.len());
        flipped[at] ^= 1 + rng.below(255) as u8;
        variants.push((flipped, attachments.clone()));
        variants.push((
            primary.clone(),
            [attachments.clone(), vec![Vec::new()]].concat(),
        ));
        if !attachments.is_empty() {
            let mut changed = attachments.clone();
            let which = rng.below(changed.len());
            let at = rng.below(changed[which].len());
            changed[which][at] ^= 1 + rng.below(255) as u8;
            variants.push((primary.clone(), changed));
            variants.push((
                primary.clone(),
                attachments[..attachments.len() - 1].to_vec(),
            ));
            // Same concatenated bytes and total, different partition.
            let mut moved = attachments.clone();
            let mut shorter = primary.clone();
            moved[0].insert(0, shorter.pop().unwrap());
            assert_ne!(
                business_input_snapshot_digest(&shorter, &moved).unwrap(),
                business_input_snapshot_digest(&primary, &attachments).unwrap(),
                "case {case}"
            );
            variants.push((shorter, moved));
        }
        if attachments.len() >= 2 && attachments.first() != attachments.last() {
            let mut reversed = attachments.clone();
            reversed.reverse();
            variants.push((primary.clone(), reversed));
        }
        for (index, (primary, attachments)) in variants.into_iter().enumerate() {
            assert_eq!(
                PreparedBusinessInputV1::prepare(&facts, primary, attachments).err(),
                Some(PreparedBusinessInputErrorV1::ContentMismatch),
                "case {case} variant {index}"
            );
        }
    }
}

#[test]
fn prepared_input_bounds_apply_before_facts_are_parsed() {
    let limit = MAX_BUSINESS_INLINE_BYTES as usize;
    let too_many = vec![Vec::new(); MAX_BUSINESS_ACTION_ITEMS + 1];
    assert_eq!(
        business_input_snapshot_digest(b"", &too_many).err(),
        Some(PreparedBusinessInputErrorV1::BoundsExceeded)
    );
    assert_eq!(
        PreparedBusinessInputV1::prepare(b"{}", Vec::new(), too_many).err(),
        Some(PreparedBusinessInputErrorV1::BoundsExceeded)
    );
    for case in 0..16 {
        let mut rng = Rng::for_case(19, case);
        for (total, expected) in [
            (limit, PreparedBusinessInputErrorV1::InvalidFacts),
            (limit + 1, PreparedBusinessInputErrorV1::BoundsExceeded),
        ] {
            let parts = 1 + rng.below(4);
            let mut sizes: Vec<usize> = (0..parts).map(|_| rng.below(total + 1)).collect();
            sizes.extend([0, total]);
            sizes.sort_unstable();
            let mut chunks = sizes.windows(2).map(|pair| vec![b'x'; pair[1] - pair[0]]);
            let primary = chunks.next().unwrap();
            let attachments: Vec<Vec<u8>> = chunks.collect();
            let digest = business_input_snapshot_digest(&primary, &attachments);
            assert_eq!(digest.is_ok(), total == limit, "case {case}");
            assert_eq!(
                PreparedBusinessInputV1::prepare(b"{}", primary, attachments).err(),
                Some(expected),
                "case {case} total {total}"
            );
        }
    }
}
