use super::*;
use crate::HostControllerKeyPins;
use std::os::unix::fs::PermissionsExt;

fn canonical(value: Value) -> Vec<u8> {
    canonicalize(value.to_string().as_bytes()).unwrap()
}

#[test]
fn one_use_effect_pin_binds_key_terminal_and_all_event_rows() {
    for version in 1..=3 {
        let handles = version >= 2;
        let images = version == 3;
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let host = HostControllerKeyPinJournal::open(&temp.path().canonicalize().unwrap()).unwrap();
        let pins = HostControllerKeyPins {
            job_id: "0123456789abcdef".to_owned(),
            source_sha: "a".repeat(40),
            deployment_digest: "b".repeat(64),
            worker_generation: "c".repeat(64),
            started_marker_sha256: "d".repeat(64),
            controller_key_pin_sha256: "e".repeat(64),
            controller_public_key_hex: "f".repeat(64),
        };
        let key = host.record(&pins).unwrap();
        let mut journal = json!({
            "schema":if images { EFFECT_IMAGE_JOURNAL_SCHEMA } else if handles { HANDLE_JOURNAL_SCHEMA } else { JOURNAL_SCHEMA },
            "run_id":pins.job_id,"source_sha":pins.source_sha,
            "started_marker_sha256":pins.started_marker_sha256,
            "controller_public_key_hex":pins.controller_public_key_hex,
            "scope":"watched-filesystem-close-write",
            "events":[{"sequence":1,"device":1,"inode":2,"owner":10001,"reported_pid":42,"pidfd_available":true,
                "writer":{"pid":42,"start_ticks":1234,"cgroup":"/product-cell.service"}}],
            "event_count":1,"unknown_writer_count":0,
            "host_pin_retained":false,"guard_causality_verified":false,"execution_eligible":false
        });
        if handles {
            journal["events"][0]["file_handle"] = json!({"kind":1,"bytes":"0123456789abcdef"});
        }
        if images {
            journal["writer_images"] = json!([{"event_sequence":1,"surface":"contained-output",
                "writer_pid":42,"writer_start_ticks":1234,"sample":null,"unavailable_reason":"process-sample-unavailable"}]);
        }
        let journal = canonical(journal);
        let report = canonical(json!({
            "schema":"hol-gauntlet-staging-control-run-report.v1",
            "run_id":pins.job_id,"source_sha":pins.source_sha,"execution_eligible":false,
            "effect_events":{"schema":if images { EFFECT_IMAGE_RECEIPT_SCHEMA } else if handles { HANDLE_RECEIPT_SCHEMA } else { RECEIPT_SCHEMA },"run_id":pins.job_id,"sha256":digest(&journal),
                "bytes":journal.len(),"events":1,"unknown_writers":0,
                "host_pin_retained":false,"guard_causality_verified":false,"execution_eligible":false}
        }));
        let terminal = canonical(json!({
            "schema":"hol-gauntlet-worker-terminal.v2",
            "job_id":pins.job_id,"source_sha":pins.source_sha,
            "deployment_digest":pins.deployment_digest,"worker_generation":pins.worker_generation,
            "started_marker_sha256":pins.started_marker_sha256,
            "controller_key_pin_sha256":pins.controller_key_pin_sha256,
            "controller_public_key_hex":pins.controller_public_key_hex,
            "report_sha256":digest(&report),"pid":321,"process_start_ticks":1234,
            "exit_code":0,"status":"invalid-evidence"
        }));
        assert_eq!(
            host.read_effect_events_pin(&pins.job_id),
            Err(HostKeyPinError::Missing)
        );
        let pin = host
            .record_effect_events_ineligible(&pins.job_id, &terminal, &report, &journal)
            .unwrap();
        assert_eq!((pin.events, pin.unknown_writers), (1, 0));
        let tap = HostSdkTapJournalPin {
            run_id: pins.job_id.clone(),
            host_key_record_sha256: key.raw_sha256.clone(),
            terminal_sha256: pin.terminal_sha256.clone(),
            report_sha256: pin.report_sha256.clone(),
            journal_sha256: "1".repeat(64),
            journal_bytes: 128,
            sessions: 2,
            events: 24,
            observed_bytes: 2048,
            raw_sha256: "2".repeat(64),
        };
        key.match_effect_events_tap_ineligible(&tap, &pin).unwrap();
        let mut wrong_tap = tap.clone();
        wrong_tap.report_sha256 = "3".repeat(64);
        assert_eq!(
            key.match_effect_events_tap_ineligible(&wrong_tap, &pin),
            Err(HostKeyPinError::InvalidEffectJournal)
        );
        assert_eq!(host.read_effect_events_pin(&pins.job_id).unwrap(), pin);
        assert_eq!(
            host.verify_effect_events_ineligible(&pins.job_id, &terminal, &report, &journal)
                .unwrap(),
            pin
        );
        assert_eq!(
            host.record_effect_events_ineligible(&pins.job_id, &terminal, &report, &journal),
            Err(HostKeyPinError::AlreadyRecorded)
        );
        let mut changed: Value = serde_json::from_slice(&journal).unwrap();
        changed["events"][0]["writer"]["pid"] = json!(43);
        assert!(host
            .verify_effect_events_ineligible(
                &pins.job_id,
                &terminal,
                &report,
                &canonical(changed.clone())
            )
            .is_err());
        assert!(key
            .observe_effect_events_ineligible(&terminal, &report, &canonical(changed))
            .is_err());
        let mut changed: Value = serde_json::from_slice(&journal).unwrap();
        changed["unknown_writer_count"] = json!(1);
        assert!(key
            .observe_effect_events_ineligible(&terminal, &report, &canonical(changed))
            .is_err());
        let mut changed: Value = serde_json::from_slice(&report).unwrap();
        changed["effect_events"]["sha256"] = json!("0".repeat(64));
        let changed_report = canonical(changed);
        assert!(key
            .observe_effect_events_ineligible(&terminal, &changed_report, &journal)
            .is_err());

        let mut zero_journal: Value = serde_json::from_slice(&journal).unwrap();
        zero_journal["events"] = json!([]);
        zero_journal["event_count"] = json!(0);
        if images {
            zero_journal["writer_images"] = json!([]);
        }
        let zero_journal = canonical(zero_journal);
        let mut zero_report: Value = serde_json::from_slice(&report).unwrap();
        zero_report["effect_events"]["sha256"] = json!(digest(&zero_journal));
        zero_report["effect_events"]["bytes"] = json!(zero_journal.len());
        zero_report["effect_events"]["events"] = json!(0);
        let zero_report = canonical(zero_report);
        let mut zero_terminal: Value = serde_json::from_slice(&terminal).unwrap();
        zero_terminal["report_sha256"] = json!(digest(&zero_report));
        let zero_terminal = canonical(zero_terminal);
        assert_eq!(
            key.observe_effect_events_ineligible(&zero_terminal, &zero_report, &zero_journal)
                .unwrap()
                .events,
            0
        );
        let zero_directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            zero_directory.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let zero_host =
            HostControllerKeyPinJournal::open(&zero_directory.path().canonicalize().unwrap())
                .unwrap();
        zero_host.record(&pins).unwrap();
        let zero_pin = zero_host
            .record_effect_events_ineligible(
                &pins.job_id,
                &zero_terminal,
                &zero_report,
                &zero_journal,
            )
            .unwrap();
        assert_eq!((zero_pin.events, zero_pin.unknown_writers), (0, 0));
        assert_eq!(
            zero_host.read_effect_events_pin(&pins.job_id).unwrap(),
            zero_pin
        );
        if handles {
            // Recompute outer hashes so these checks exercise the v2 shape,
            // not merely refusal of altered unpinned bytes.
            let read_changed = |changed: Value| {
                let raw = canonical(changed);
                let mut report: Value = serde_json::from_slice(&report).unwrap();
                report["effect_events"]["sha256"] = json!(digest(&raw));
                report["effect_events"]["bytes"] = json!(raw.len());
                let report = canonical(report);
                let mut terminal: Value = serde_json::from_slice(&terminal).unwrap();
                terminal["report_sha256"] = json!(digest(&report));
                key.observe_effect_events_ineligible(&canonical(terminal), &report, &raw)
            };
            let original: Value = serde_json::from_slice(&journal).unwrap();
            let mut missing = original.clone();
            missing["events"][0]
                .as_object_mut()
                .unwrap()
                .remove("file_handle");
            assert!(read_changed(missing).is_err());
            let mut unknown = original.clone();
            unknown["events"][0]["file_handle"] = Value::Null;
            // A v3 image reference cannot outlive its file-generation observation.
            assert_eq!(read_changed(unknown).is_ok(), !images);
            let mut malformed = original.clone();
            malformed["events"][0]["file_handle"]["kind"] = json!(true);
            assert!(read_changed(malformed).is_err());
            let mut wrong_version = original.clone();
            wrong_version["schema"] = json!(JOURNAL_SCHEMA);
            assert!(read_changed(wrong_version).is_err());
            if images {
                for (path, value) in [
                    ("/writer_images/0/writer_pid", json!(43)),
                    ("/writer_images/0/event_sequence", json!(2)),
                    ("/writer_images/0/unavailable_reason", Value::Null),
                    ("/writer_images", Value::Null),
                ] {
                    let mut malformed = original.clone();
                    *malformed.pointer_mut(path).unwrap() = value;
                    assert!(read_changed(malformed).is_err(), "{path}");
                }
                let mut downgrade = original;
                downgrade["schema"] = json!(HANDLE_JOURNAL_SCHEMA);
                assert!(read_changed(downgrade).is_err());
            }
        }
    }
}
