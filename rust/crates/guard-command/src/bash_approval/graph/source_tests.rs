use super::*;
#[cfg(unix)]
use std::process::Command;

struct Sources(BTreeMap<String, String>);

#[test]
fn repeated_sources_share_one_captured_byte_allocation() {
    struct Shared(std::sync::Arc<str>);
    impl Resolver for Shared {
        fn resolve(&self, _: &[String]) -> std::result::Result<Executable, &'static str> {
            Err("unresolved")
        }
        fn resolve_source(&self, path: &str) -> std::result::Result<Code, &'static str> {
            Ok(Code {
                original_path: path.into(),
                resolved_path: "/config".into(),
                source: self.0.clone(),
            })
        }
    }
    let bytes: std::sync::Arc<str> = format!("#{}\nsetting=ready\n", "x".repeat(128 * 1024)).into();
    let resolver = Shared(bytes.clone());
    let entry = Code {
        original_path: "/entry".into(),
        resolved_path: "/entry".into(),
        source: format!("for item in {}; do . /config; done", "value ".repeat(64)).into(),
    };
    // This checks allocation sharing, not the separate installed-latency target.
    let analysis = crate::bash_approval::source::analyze(
        &entry,
        &["/entry".into()],
        &BTreeMap::new(),
        &resolver,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(analysis.sources.len(), 64);
    assert!(analysis
        .sources
        .iter()
        .all(|source| std::sync::Arc::ptr_eq(&bytes, &source.code.source)));
}

impl Resolver for Sources {
    fn resolve(&self, argv: &[String]) -> std::result::Result<Executable, &'static str> {
        FixtureResolver.resolve(argv)
    }
    fn resolve_source(&self, path: &str) -> std::result::Result<Code, &'static str> {
        Ok(Code {
            original_path: path.into(),
            resolved_path: format!("/fixtures/{}", path.trim_start_matches("./")),
            source: self
                .0
                .get(path)
                .ok_or("bash_source_unresolved")?
                .clone()
                .into(),
        })
    }
}

fn captured(script: &str, sources: &Sources) -> Result<Graph> {
    build(
        Code {
            original_path: "original-script.sh".into(),
            resolved_path: "/fixtures/original-script.sh".into(),
            source: script.into(),
        },
        &["original-script.sh".into(), "dry".into()],
        &BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
        sources,
        Instant::now() + Duration::from_secs(1),
    )
}

#[cfg(unix)]
fn compare(script: &str, sources: Sources) -> Graph {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("original-script.sh"), script).unwrap();
    for (path, content) in &sources.0 {
        std::fs::write(
            directory.path().join(path.trim_start_matches("./")),
            content,
        )
        .unwrap();
    }
    let graph = captured(script, &sources).unwrap();
    let original = Command::new("/bin/bash")
        .args(["original-script.sh", "dry"])
        .current_dir(directory.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    // Every source pathname now has different bytes. Frozen execution must
    // neither reopen those files nor lose the source's shared shell state.
    for (index, path) in sources.0.keys().enumerate() {
        if index % 2 == 0 {
            std::fs::remove_file(directory.path().join(path.trim_start_matches("./"))).unwrap();
        }
        std::fs::write(
            directory.path().join(path.trim_start_matches("./")),
            "printf mutated; exit 99",
        )
        .unwrap();
    }
    let frozen = Command::new("/bin/bash")
        .args([
            "--noprofile",
            "--norc",
            "-c",
            graph.source_for_launch().unwrap(),
            "original-script.sh",
            "dry",
        ])
        .current_dir(directory.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert_eq!(frozen.status.code(), original.status.code());
    assert_eq!(frozen.stdout, original.stdout);
    assert_eq!(frozen.stderr, original.stderr);
    graph
}

#[test]
#[cfg(unix)]
fn literal_sources_share_variables_argv_and_cwd_without_reopening_files() {
    let graph = compare(
        "value=before; source ./config; printf '%s\\n' \"$value\"",
        Sources(BTreeMap::from([(
            "./config".into(),
            "value=after; printf '%s\\n%s\\n' \"$0\" \"$1\"".into(),
        )])),
    );
    assert_eq!(graph.sources.len(), 1);
    assert!(graph
        .invocations
        .iter()
        .any(|call| call.operation.argv == ["source", "./config"]));
    assert!(graph
        .invocations
        .iter()
        .any(|call| call.operation.argv == ["printf", "%s\\n", "after"]));
}

#[test]
#[cfg(unix)]
fn nested_sources_keep_pipeline_scope_and_empty_source_status() {
    let graph = compare(
        "value=outer; . ./first | head -n 2; printf '%s' \"$value\"",
        Sources(BTreeMap::from([
            (
                "./first".into(),
                "value=inner; source ./second; printf '%s\\n' \"$value\"".into(),
            ),
            ("./second".into(), "value=nested".into()),
        ])),
    );
    assert_eq!(graph.sources.len(), 2);
    compare(
        "false; source ./empty; exit",
        Sources(BTreeMap::from([(
            "./empty".into(),
            "# comments only".into(),
        )])),
    );
    compare(
        "false; source ./stop; printf unreachable",
        Sources(BTreeMap::from([("./stop".into(), "exit".into())])),
    );
}

#[test]
fn sourced_mode_controls_reachable_operations_and_unreachable_sources_stay_unread() {
    let script = "source ./mode; case \"$mode\" in dry) printf safe;; *) rm /protected;; esac";
    let dry = captured(
        script,
        &Sources(BTreeMap::from([("./mode".into(), "mode=dry".into())])),
    )
    .unwrap();
    let delete = captured(
        script,
        &Sources(BTreeMap::from([("./mode".into(), "mode=delete".into())])),
    )
    .unwrap();
    assert!(!dry.native_images.contains_key("/bin/rm"));
    assert!(delete.native_images.contains_key("/bin/rm"));
    assert_ne!(
        dry.sources[0].content_sha256,
        delete.sources[0].content_sha256
    );
    let unreachable = captured(
        "case \"$1\" in dry) printf safe;; *) source ./missing;; esac",
        &Sources(BTreeMap::new()),
    )
    .unwrap();
    assert!(unreachable.sources.is_empty());
}

#[test]
fn source_cycles_returns_and_positional_overrides_never_return_partial_graphs() {
    let cases = [
        (
            "source ./a",
            Sources(BTreeMap::from([
                ("./a".into(), "source ./b".into()),
                ("./b".into(), "source ./a".into()),
            ])),
            "bash_source_cycle",
        ),
        (
            "source ./a extra",
            Sources(BTreeMap::from([("./a".into(), "printf safe".into())])),
            "bash_source_arguments_unproven",
        ),
        (
            "source ./a",
            Sources(BTreeMap::from([(
                "./a".into(),
                "printf safe; return".into(),
            )])),
            "bash_source_return_unproven",
        ),
    ];
    for (script, sources, reason) in cases {
        assert_eq!(captured(script, &sources).unwrap_err().reason, reason);
    }
}
