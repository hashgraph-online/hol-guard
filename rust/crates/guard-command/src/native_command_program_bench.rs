//! Component measurements only; installed latency remains a separate gate.
use super::*;
use std::hint::black_box;

fn distribution(mut values: Vec<f64>) -> serde_json::Value {
    values.sort_by(f64::total_cmp);
    serde_json::json!({
        "samples": values.len(), "p50_us": values[(values.len() - 1) / 2],
        "p95_us": values[(95 * values.len()).div_ceil(100) - 1],
        "max_us": values[values.len() - 1],
    })
}

#[test]
#[ignore = "diagnostic component timing; run release mode explicitly"]
fn native_command_program_component_diagnostic() {
    let mut admission = Vec::new();
    let mut phases = BTreeMap::<&'static str, Vec<f64>>::new();
    for _ in 0..100 {
        let started = Instant::now();
        let mut last = started;
        let mut observed = Vec::with_capacity(6);
        let admitted = black_box(
            NativeCommandProgram::from_packaged_bytes_observed(
                black_box(EMBEDDED_PROGRAM),
                |phase| {
                    let now = Instant::now();
                    observed.push((phase, now.duration_since(last).as_secs_f64() * 1_000_000.0));
                    last = now;
                },
            )
            .unwrap(),
        );
        admission.push(started.elapsed().as_secs_f64() * 1_000_000.0);
        observed.push(("value_cleanup", last.elapsed().as_secs_f64() * 1_000_000.0));
        // A resident retains the admitted program. Its eventual destruction is
        // not part of cold readiness, so keep it outside the timed interval.
        drop(admitted);
        for (phase, duration) in observed {
            phases.entry(phase).or_default().push(duration);
        }
    }
    println!(
        "{}",
        serde_json::json!({"stage":"cold_program_admission", "distribution":distribution(admission)})
    );
    for (phase, samples) in phases {
        println!(
            "{}",
            serde_json::json!({"stage":"cold_program_admission_phase", "phase":phase, "distribution":distribution(samples)})
        );
    }
    let program = packaged_command_program().unwrap();
    let active = program
        .extensions
        .iter()
        .map(|extension| extension.extension_id.clone())
        .collect();
    for source in [
        "ollama push model",
        "ollama push model --help",
        "ollama rm first && ollama push second",
        "aws s3 rm s3://bucket/key",
        "printf café",
    ] {
        let request = serde_json::from_value(serde_json::json!({"command":source})).unwrap();
        let command = crate::parse_command(&request).unwrap();
        let expected = program.observe(&command, &active, None).unwrap();
        let mut observation = Vec::new();
        let mut parsing = Vec::new();
        for _ in 0..100 {
            let started = Instant::now();
            black_box(crate::parse_command(black_box(&request)).unwrap());
            parsing.push(started.elapsed().as_secs_f64() * 1_000_000.0);
            let started = Instant::now();
            let actual = black_box(
                program
                    .observe(black_box(&command), black_box(&active), None)
                    .unwrap(),
            );
            observation.push(started.elapsed().as_secs_f64() * 1_000_000.0);
            assert_eq!(actual, expected);
        }
        println!(
            "{}",
            serde_json::json!({"stage":"warm_native_program", "command":source, "parse":distribution(parsing), "observe":distribution(observation), "candidate_rules":program.candidate_rule_indices(&command).len(), "rules":program.rules.len()})
        );
    }
}
