//! Diagnostic alternative only. Adoption requires installed-path evidence;
//! these measurements must not change scanner semantics or release budgets.
use super::*;
use regex::RegexSet;

fn prefilter() -> RegexSet {
    RegexSet::new(PATTERNS.iter().map(|def| {
        let mut flags = String::new();
        if def.case_insensitive {
            flags.push('i');
        }
        if def.multi_line {
            flags.push('m');
        }
        format!("(?{flags}:{})", def.pattern)
    }))
    .unwrap()
}

fn classify_prefiltered(
    text: &str,
    suppress_samples: bool,
    documentation_sample_context: bool,
    set: &RegexSet,
) -> BTreeMap<&'static str, ScanMatch> {
    let candidates = set.matches(text);
    let mut found = BTreeMap::new();
    for index in candidates.iter() {
        let def = &PATTERNS[index];
        if compiled()[index].find_iter(text).any(|matched| {
            !is_sample(
                def.classifier,
                matched.as_str(),
                suppress_samples,
                documentation_sample_context,
            )
        }) {
            found.insert(
                def.classifier,
                ScanMatch {
                    classifier: def.classifier,
                    family: def.family,
                    sensitivity: def.sensitivity,
                    reason: def.reason,
                },
            );
        }
    }
    found
}

fn fixtures() -> Vec<(&'static str, String)> {
    vec![
        ("clean_16k", "plain output\n".repeat(1366)),
        ("clean_1m", "plain output\n".repeat(87_382)),
        (
            "matching_16k",
            format!("{}\nghp_{}", "ordinary\n".repeat(1820), "a".repeat(30)),
        ),
        (
            "samples_16k",
            "secret = get_secret('deployment-config')\npassword = placeholder-only\n".repeat(256),
        ),
    ]
}

#[test]
fn prefilter_retains_per_match_suppression_and_ordering() {
    let set = prefilter();
    let mut fixtures = fixtures();
    fixtures.push((
        "mixed",
        format!(
            "token = placeholder-only\npassword = example-production-value\nghp_{}\nAKIA{}",
            "b".repeat(30),
            "A".repeat(16)
        ),
    ));
    for (_, text) in fixtures {
        for suppress in [false, true] {
            for documentation in [false, true] {
                let mut expected = BTreeMap::new();
                classify_window(&text, suppress, documentation, &mut expected);
                assert_eq!(
                    classify_prefiltered(&text, suppress, documentation, &set),
                    expected
                );
            }
        }
    }
}

#[test]
#[ignore = "diagnostic release microbenchmark; not an installed latency gate"]
fn benchmark_scanner_prefilter() {
    use std::hint::black_box;
    let set = prefilter();
    for (name, text) in fixtures() {
        let mut reference = BTreeMap::new();
        classify_window(&text, true, true, &mut reference);
        assert_eq!(classify_prefiltered(&text, true, true, &set), reference);
        let mut baseline = Vec::new();
        let mut candidate = Vec::new();
        for round in 0..5 {
            for _ in 0..20 {
                for optimized in [round % 2 == 0, round % 2 != 0] {
                    let started = Instant::now();
                    let result = if optimized {
                        classify_prefiltered(black_box(&text), true, true, &set)
                    } else {
                        let mut found = BTreeMap::new();
                        classify_window(black_box(&text), true, true, &mut found);
                        found
                    };
                    black_box(result);
                    let micros = started.elapsed().as_secs_f64() * 1_000_000.0;
                    if optimized {
                        candidate.push(micros);
                    } else {
                        baseline.push(micros);
                    }
                }
            }
        }
        baseline.sort_by(f64::total_cmp);
        candidate.sort_by(f64::total_cmp);
        println!("{{\"benchmark\":\"scanner_prefilter\",\"fixture\":\"{name}\",\"samples\":100,\"baseline_p95_us\":{},\"candidate_p95_us\":{}}}", baseline[94], candidate[94]);
    }
}
