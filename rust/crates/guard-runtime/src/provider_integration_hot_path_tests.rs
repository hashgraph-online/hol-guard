//! Hot path proof for provider signals (PRD 6.6, BP-T124).
//!
//! The hook and relay decision paths read the provider signal cache only. They never send a
//! provider request and never wait on the provider worker. Two checks hold that line:
//!
//! - The items that can reach a provider or the worker may be named only by the modules that own
//!   them. A hook or relay module that names one of them fails this test, so the decision path
//!   cannot start calling a provider by accident.
//! - The decide step, the one provider module the decision path may call, names no network, thread,
//!   channel, process or sleep primitive, and its p95 over a cached subject stays inside
//!   `MAX_PROVIDER_DECIDE_P95_MS`, which `scripts/native_slo_contract.py` mirrors.

use std::path::{Path, PathBuf};
use std::time::Instant;

use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderConnectionStateV1 as State, ProviderInventoryV1,
    ProviderSignalStateV1, ProviderSignalV1, ProviderSubjectKindV1, ProviderSubjectV1,
    ProviderVerdictV1 as Verdict, PROVIDER_SIGNAL_V1_VERSION,
};
use guard_provider_integrations::noise::{BaselineDecision, NoiseLedger};
use rusqlite::Connection;

use crate::provider_integration_decide::{decide, DecideProvider, DecideRequest};
use crate::provider_integration_managed::ManagedProviderSettings;
use crate::provider_integration_store::{
    ensure_provider_integration_schema, put_connection, put_signal, ProviderConnection,
};

/// The decide step's p95 ceiling for one cached subject. Mirrored by
/// `MAX_PROVIDER_DECIDE_P95_MS` in `scripts/native_slo_contract.py`.
pub(crate) const MAX_PROVIDER_DECIDE_P95_MS: f64 = 2.0;

/// Items that can send a provider request or hold the decision for the worker.
const NETWORK_OR_WORKER_ITEMS: &[&str] = &[
    "provider_integration_lookup",
    "provider_integration_worker",
    "ProviderWorker",
    "ProviderTransport",
    "HttpProviderTransport",
    "FixtureProviderTransport",
    "FakeProvider",
    "guard_provider_integrations::client",
    "guard_provider_integrations::testkit",
    "guard_provider_integrations::fixture_origin",
];

/// The modules allowed to name those items: their owners and their tests. `lib.rs` is scanned like
/// any other file apart from the module declarations in `MODULE_DECLARATIONS`.
/// The connect route checks a key with the provider, so its route module and the daemon edge that
/// runs it are owners too. The daemon's background scheduler joins this list when it lands, never
/// a hook or relay module.
const OWNERS: &[&str] = &[
    "daemon_edge_integrations.rs",
    "daemon_edge_integrations_tests.rs",
    "provider_integration_hot_path_tests.rs",
    "provider_integration_lookup.rs",
    "provider_integration_lookup_tests.rs",
    "provider_integration_routes_connect.rs",
    "provider_integration_routes_connect_tests.rs",
    "provider_integration_routes_lookup.rs",
    "provider_integration_routes_lookup_tests.rs",
    "provider_integration_worker.rs",
    "provider_integration_worker_tests.rs",
    "secret_provider_adapter.rs",
];

/// The only lines of `lib.rs` that may name an owner module.
const MODULE_DECLARATIONS: &[&str] = &[
    "pub mod provider_integration_lookup;",
    "pub mod provider_integration_worker;",
    "mod provider_integration_hot_path_tests;",
];

/// Primitives that perform I/O beyond the local store or that wait.
const BLOCKING_PRIMITIVES: &[&str] = &[
    "std::net",
    "std::thread",
    "std::process",
    "std::sync::mpsc",
    "Condvar",
    "sleep(",
    "tokio",
    "reqwest",
    "ureq",
    "hyper",
    "rustls",
    "TcpStream",
    "UdpSocket",
    ".recv(",
    ".join(",
];

fn source_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The file's code with whole-line comments removed, so prose about the worker does not count.
fn code_of(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn only_the_owners_name_an_item_that_reaches_a_provider_or_the_worker() {
    let root = source_root();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    assert!(files.len() > 100, "the source walk found too few files");
    let mut offenders = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        if OWNERS.contains(&relative.as_str()) {
            continue;
        }
        let code: String = code_of(&path)
            .lines()
            .filter(|line| relative != "lib.rs" || !MODULE_DECLARATIONS.contains(&line.trim()))
            .collect::<Vec<_>>()
            .join("\n");
        for item in NETWORK_OR_WORKER_ITEMS {
            if code.contains(item) {
                offenders.push(format!("{relative}: {item}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the decision path must read the provider cache only: {offenders:?}"
    );
}

#[test]
fn the_decide_step_names_no_network_worker_or_waiting_primitive() {
    let code = code_of(&source_root().join("provider_integration_decide.rs"));
    let named: Vec<&str> = NETWORK_OR_WORKER_ITEMS
        .iter()
        .chain(BLOCKING_PRIMITIVES)
        .copied()
        .filter(|item| code.contains(item))
        .collect();
    assert!(
        named.is_empty(),
        "provider_integration_decide.rs names {named:?}"
    );
}

#[test]
fn lib_rs_is_scanned_apart_from_its_module_declarations() {
    let lib = std::fs::read_to_string(source_root().join("lib.rs")).unwrap();
    for declaration in MODULE_DECLARATIONS {
        assert!(
            lib.lines().any(|line| line.trim() == *declaration),
            "{declaration} is not in lib.rs"
        );
    }
    assert!(!OWNERS.contains(&"lib.rs"));
}

#[test]
fn the_owner_list_still_names_real_files() {
    let root = source_root();
    for owner in OWNERS {
        assert!(root.join(owner).is_file(), "{owner} is not a source file");
    }
}

fn digest(n: u64) -> String {
    format!("{n:064x}")
}

#[test]
fn deciding_a_cached_subject_stays_inside_the_latency_budget() {
    const PROVIDERS: [&str; 3] = [
        "provider.exampleshield",
        "provider.otherwatch",
        "provider.fixture-third",
    ];
    const NOW: u64 = 10_000_000;
    let connection = Connection::open_in_memory().unwrap();
    ensure_provider_integration_schema(&connection).unwrap();
    for (index, provider_id) in PROVIDERS.iter().enumerate() {
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
        put_signal(
            &connection,
            &ProviderSignalV1 {
                version: PROVIDER_SIGNAL_V1_VERSION,
                provider_id: (*provider_id).to_owned(),
                capability: Cap::OriginReputation,
                subject: ProviderSubjectV1 {
                    kind: ProviderSubjectKindV1::Origin,
                    digest: digest(1),
                },
                verdict: [Verdict::Ok, Verdict::Caution, Verdict::Danger][index],
                reason_codes: vec!["phishing".to_owned()],
                observed_at_ms: NOW - 1_000,
                expires_at_ms: NOW + 60_000,
                inventory: ProviderInventoryV1::None,
                state: ProviderSignalStateV1::Fresh,
            },
        )
        .unwrap();
    }
    let providers: Vec<DecideProvider<'_>> = PROVIDERS
        .iter()
        .map(|provider_id| DecideProvider {
            provider_id,
            verified: true,
        })
        .collect();
    let subject = digest(1);
    let request = DecideRequest {
        baseline: BaselineDecision::Allow,
        capability: Cap::OriginReputation,
        subject_digest: &subject,
        providers: &providers,
        now_ms: NOW,
        managed: &ManagedProviderSettings::none(),
    };
    let mut samples = Vec::with_capacity(400);
    for round in 0..440 {
        let mut ledger = NoiseLedger::new();
        let started = Instant::now();
        let decided = decide(&connection, &mut ledger, &request).unwrap();
        let elapsed = started.elapsed().as_secs_f64() * 1_000.0;
        assert_eq!(decided.decision, BaselineDecision::Review);
        if round >= 40 {
            samples.push(elapsed);
        }
    }
    samples.sort_by(f64::total_cmp);
    let p95 = samples[samples.len() * 95 / 100];
    // The SLO holds for optimised builds. Debug and coverage-instrumented CI runs share the CPU with
    // other tests, so they only catch a decide step that has become grossly slow (a network wait
    // would be far over either bound).
    let budget = if cfg!(debug_assertions) {
        MAX_PROVIDER_DECIDE_P95_MS * 25.0
    } else {
        MAX_PROVIDER_DECIDE_P95_MS
    };
    assert!(p95 <= budget, "decide p95 {p95:.3} ms is over {budget} ms");
}
