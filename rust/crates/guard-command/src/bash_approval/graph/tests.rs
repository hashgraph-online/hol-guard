use sha2::{Digest, Sha256};
use std::time::Duration;

use super::*;

#[path = "source_tests.rs"]
mod source_tests;

const SCRIPT: &str =
    include_str!("../../../../../../tests/fixtures/script_approvals/maintenance.sh");
const HELPER: &str =
    include_str!("../../../../../../tests/fixtures/script_approvals/fixture-registry");

struct FixtureResolver;

#[test]
fn held_outputs_reject_later_truncation() {
    for source in [
        "printf a >/report; printf b >/report",
        "printf a >>/report; printf b >/report",
        "for item in a b; do printf a >/report; done",
    ] {
        let result = build_with_outputs(
            Code {
                original_path: "/script.sh".into(),
                resolved_path: "/script.sh".into(),
                source: source.into(),
            },
            &["/script.sh".into()],
            &BTreeMap::new(),
            &FixtureResolver,
            Instant::now() + Duration::from_secs(1),
            &BTreeMap::from([("/report".into(), 6)]),
        );
        assert_eq!(result.unwrap_err().reason, "bash_output_order_unproven");
    }
}

impl Resolver for FixtureResolver {
    fn resolve(&self, argv: &[String]) -> std::result::Result<Executable, &'static str> {
        let command = argv[0].as_str();
        match command {
            "fixture-registry" => Ok(Executable::Bash(Code {
                original_path: "/fixtures/fixture-registry".into(),
                resolved_path: "/fixtures/fixture-registry".into(),
                source: HELPER.into(),
            })),
            "sort" | "head" => Ok(Executable::Native {
                resolved_path: format!("/usr/bin/{command}"),
                content_sha256: "1".repeat(64),
            }),
            "rm" => Ok(Executable::Native {
                resolved_path: "/bin/rm".into(),
                content_sha256: "2".repeat(64),
            }),
            _ => Err("bash_helper_unresolved"),
        }
    }
}

fn graph(mode: &str) -> Graph {
    build(
        Code {
            original_path: "/fixtures/maintenance.sh".into(),
            resolved_path: "/fixtures/maintenance.sh".into(),
            source: SCRIPT.into(),
        },
        &["/fixtures/maintenance.sh".into(), mode.into()],
        &BTreeMap::from([("HOME".into(), "/isolated/home".into())]),
        &FixtureResolver,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap()
}

#[test]
fn graph_subject_binds_observed_inputs_without_granting_execution() {
    use crate::bash_approval::subject::{from_graph, Observations};
    use guard_contracts::{
        NativeBashContextV1, NativeBashHostV1, NativeScriptCodeInputV1, NativeScriptInputKindV1,
    };

    let dry = graph("dry");
    let argv = ["/fixtures/maintenance.sh".into(), "dry".into()];
    let environment = BTreeMap::from([("HOME".into(), "/isolated/home".into())]);
    let resolved = BTreeMap::from([(
        "/isolated/home/maintenance-report.tsv".into(),
        "/isolated/home/maintenance-report.tsv".into(),
    )]);
    let observed = |outputs| Observations {
        context: NativeBashContextV1 {
            host: NativeBashHostV1::OmpInputRewriteV1,
            host_scope_digest: "a".repeat(64),
            guard_home_scope_digest: "b".repeat(64),
            project: "/fixtures".into(),
            cwd: "/fixtures".into(),
            home: "/isolated/home".into(),
            file_creation_mask: Some(0o022),
        },
        argv: &argv,
        interpreter: NativeScriptCodeInputV1 {
            kind: NativeScriptInputKindV1::Interpreter,
            requested_path: "/bin/bash".into(),
            resolved_path: "/bin/bash".into(),
            content_sha256: "c".repeat(64),
        },
        environment: &environment,
        resolved_outputs: outputs,
    };
    let unresolved = BTreeMap::new();
    assert_eq!(
        from_graph(&dry, observed(&unresolved)).unwrap_err(),
        "native_bash_subject_output_unresolved"
    );
    let subject = from_graph(&dry, observed(&resolved)).unwrap();
    assert_eq!(subject.code_inputs.len(), 5);
    assert_eq!(subject.invocations.len(), dry.invocations.len());
    assert_eq!(subject.outputs.len(), 5);
    assert_ne!(subject.environment_bindings["HOME"], environment["HOME"]);
    assert_eq!(
        subject.identity_sha256().unwrap(),
        from_graph(&graph("dry"), observed(&resolved))
            .unwrap()
            .identity_sha256()
            .unwrap()
    );
    assert!(
        dry.source_for_launch().is_err(),
        "a descriptor must not bind output handles or grant a launch"
    );
}

#[test]
fn graph_includes_helper_bytes_and_every_reachable_parent_and_child() {
    let dry = graph("dry");
    let delete = graph("delete");
    assert_eq!(dry.code.len(), 2);
    assert_eq!(
        dry.code[0].content_sha256,
        hex::encode(Sha256::digest(HELPER))
    );
    assert_eq!(dry.native_images.len(), 2);
    assert!(!dry.native_images.contains_key("/bin/rm"));
    assert!(delete.native_images.contains_key("/bin/rm"));
    assert_eq!(
        dry.invocations
            .iter()
            .filter(|call| call.operation.argv[0] == "fixture-registry")
            .count(),
        4
    );
    assert_eq!(
        dry.invocations
            .iter()
            .filter(|call| call.operation.argv[0] == "printf")
            .count(),
        4
    );
    assert_eq!(dry.writes.len(), 5);
    assert!(dry
        .frozen_source
        .contains("/bin/bash --noprofile --norc -c"));
    assert_eq!(
        dry.source_for_launch().unwrap_err().reason,
        "bash_output_handles_required"
    );
}

#[test]
fn output_rendering_requires_a_complete_contiguous_descriptor_table() {
    let entry = || Code {
        original_path: "/entry".into(),
        resolved_path: "/entry".into(),
        source: ": > '/reports/result'\nprintf x >> '/reports/result'".into(),
    };
    let run = |fds: &BTreeMap<String, u32>| {
        build_with_outputs(
            entry(),
            &["/entry".into()],
            &BTreeMap::new(),
            &FixtureResolver,
            Instant::now() + Duration::from_secs(1),
            fds,
        )
    };
    assert_eq!(
        run(&BTreeMap::new()).unwrap_err().reason,
        "bash_output_handle_missing"
    );
    assert_eq!(
        run(&BTreeMap::from([("/reports/result".into(), 69)]))
            .unwrap_err()
            .reason,
        "bash_output_descriptor_bounds"
    );
    let graph = run(&BTreeMap::from([("/reports/result".into(), 6)])).unwrap();
    assert_eq!(graph.source_for_launch().unwrap(), ": >&6\nprintf x >&6");
}

#[cfg(target_os = "macos")]
#[path = "kernel_tests.rs"]
mod kernel;

#[test]
fn recursive_or_unresolved_helpers_never_return_a_partial_graph() {
    struct Recursive;
    impl Resolver for Recursive {
        fn resolve(&self, _: &[String]) -> std::result::Result<Executable, &'static str> {
            Ok(Executable::Bash(Code {
                original_path: "/cycle".into(),
                resolved_path: "/cycle".into(),
                source: "cycle".into(),
            }))
        }
    }
    let source = Code {
        original_path: "/entry".into(),
        resolved_path: "/entry".into(),
        source: "cycle".into(),
    };
    let result = build(
        source,
        &["/entry".into()],
        &BTreeMap::new(),
        &Recursive,
        Instant::now() + Duration::from_secs(1),
    );
    assert_eq!(result.unwrap_err().reason, "bash_helper_cycle");
    let source = Code {
        original_path: "/entry".into(),
        resolved_path: "/entry".into(),
        source: "unknown".into(),
    };
    assert_eq!(
        build(
            source,
            &["/entry".into()],
            &BTreeMap::new(),
            &FixtureResolver,
            Instant::now() + Duration::from_secs(1)
        )
        .unwrap_err()
        .reason,
        "bash_helper_unresolved"
    );
}

#[cfg(unix)]
#[test]
fn frozen_native_call_preserves_original_argv_zero() {
    struct NativeBash;
    impl Resolver for NativeBash {
        fn resolve(&self, _: &[String]) -> std::result::Result<Executable, &'static str> {
            Ok(Executable::Native {
                resolved_path: "/bin/bash".into(),
                content_sha256: "a".repeat(64),
            })
        }
    }
    let graph = build(
        Code {
            original_path: "/entry".into(),
            resolved_path: "/entry".into(),
            source: "named-utility --noprofile --norc -c 'printf %s \"$0\"'".into(),
        },
        &["/entry".into()],
        &BTreeMap::new(),
        &NativeBash,
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    let result = std::process::Command::new("/bin/bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            graph.source_for_launch().unwrap(),
            "/entry",
        ])
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"named-utility");
}

#[cfg(unix)]
#[test]
fn frozen_dry_graph_runs_without_opening_mutable_entry_or_helper_paths() {
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "guard-frozen-bash-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    let graph = graph("dry");
    let result = Command::new("/bin/bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            &graph.frozen_source,
            "/fixtures/maintenance.sh",
            "dry",
        ])
        .env_clear()
        .env("HOME", &root)
        .env("PATH", "/unavailable")
        .current_dir(&root)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(std::fs::read_to_string(root.join("maintenance-report.tsv")).unwrap(), "alpha/current\nalpha/obsolete\nalpha\tlocal metadata\nbeta/current\nbeta/obsolete\nbeta\tlocal metadata\n");
    std::fs::remove_dir_all(root).unwrap();
}
