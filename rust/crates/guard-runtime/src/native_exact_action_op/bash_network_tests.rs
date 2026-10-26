//! Real system curl, local registry, frozen helper and kernel egress checks.
use super::*;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

const HTTP_HELPER: &str =
    include_str!("../../../../../tests/fixtures/script_approvals/fixture-http-registry");

struct Registry {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Registry {
    fn start() -> Self {
        let listener = (3000..=3010)
            .chain(8000..=8010)
            .find_map(|port| TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).ok())
            .expect("isolated registry needs an available development port");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let records = seen.clone();
        let stop = stopped.clone();
        let worker = std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => Self::answer(stream, &records),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("registry accept failed: {error}"),
                }
            }
        });
        Self {
            port,
            seen,
            stopped,
            worker: Some(worker),
        }
    }

    fn answer(mut stream: TcpStream, seen: &Mutex<Vec<String>>) {
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut reader = BufReader::new(&stream);
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        let request = first.trim_end().to_owned();
        // Finish reading headers so closing a connection cannot reset unread
        // bytes before the response has reached curl.
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        seen.lock().unwrap().push(request.clone());
        let fields = request.split_whitespace().collect::<Vec<_>>();
        let path = fields.get(1).copied().unwrap_or("");
        let body = match (fields.first().copied(), path) {
            (Some("GET"), "/alpha/list") => "alpha/current\nalpha/obsolete\n",
            (Some("GET"), "/beta/list") => "beta/current\nbeta/obsolete\n",
            (Some("GET"), "/alpha/inspect") => "alpha\tremote metadata\n",
            (Some("GET"), "/beta/inspect") => "beta\tremote metadata\n",
            _ => "unexpected registry operation\n",
        };
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    }

    fn helper(&self) -> String {
        HTTP_HELPER.replace("127.0.0.1:3001", &format!("127.0.0.1:{}", self.port))
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let joined = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            joined.expect("registry worker failed");
        }
    }
}

struct Gate;
impl guard_contained_process::SourceLaunchGate for Gate {
    fn prepare_effects(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn commit(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn released(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn bash_real_system_curl_reads_registry_with_bound_egress_and_frozen_helper() {
    let registry = Registry::start();
    let (_root, request) = tests::fixture();
    let helper = Path::new(&request.cwd).join("fixture-registry");
    let protected = Path::new(&request.home_dir).join("protected");
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    std::fs::write(&helper, registry.helper()).unwrap();
    std::fs::write(&protected, "protected sentinel").unwrap();
    std::fs::write(
        Path::new(&request.home_dir).join(".curlrc"),
        format!(
            "data-binary = @{}\nurl = http://127.0.0.1:{}/unexpected\n",
            protected.display(),
            registry.port
        ),
    )
    .unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    assert!(
        captured.policy.as_ref().unwrap().allows_without_consent(),
        "{:?}",
        captured.policy.as_ref().unwrap().decisions
    );
    assert_eq!(
        captured.network_destinations,
        BTreeSet::from([format!("127.0.0.1:{}", registry.port).parse().unwrap()])
    );
    assert_eq!(
        captured.subject.execution_assurance,
        guard_contracts::NativeBashAssuranceV1::MacosReadonlyRootHttpReadV1
    );
    assert!(captured
        .subject
        .code_inputs
        .iter()
        .any(|input| input.kind == guard_contracts::NativeScriptInputKindV1::Startup));
    std::fs::write(
        &helper,
        format!(
            "#!/bin/bash\n/usr/bin/curl -q --data-binary @'{}' http://127.0.0.1:{}/unexpected\n",
            protected.display(),
            registry.port
        ),
    )
    .unwrap();
    let result = super::super::super::bash_launch::execute(
        captured,
        Instant::now() + Duration::from_secs(8),
        &AtomicBool::new(false),
        &mut Gate,
    )
    .unwrap();
    assert_eq!(
        result.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!result.timed_out && !result.cancelled);
    assert_eq!(
        std::fs::read_to_string(protected).unwrap(),
        "protected sentinel"
    );
    assert_eq!(std::fs::read_to_string(report).unwrap(), "alpha/current\nalpha/obsolete\nalpha\tremote metadata\nbeta/current\nbeta/obsolete\nbeta\tremote metadata\n");
    assert_eq!(
        *registry.seen.lock().unwrap(),
        [
            "GET /alpha/list HTTP/1.1",
            "GET /alpha/inspect HTTP/1.1",
            "GET /beta/list HTTP/1.1",
            "GET /beta/inspect HTTP/1.1"
        ]
    );
}

#[test]
fn bash_network_profile_denies_an_undeclared_peer_at_the_kernel() {
    let declared = Registry::start();
    let forbidden = Registry::start();
    let (_root, request) = tests::fixture();
    std::fs::write(
        Path::new(&request.cwd).join("fixture-registry"),
        declared.helper(),
    )
    .unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    let profile = super::super::super::bash_launch::profile(&captured).unwrap();
    for (port, success) in [(declared.port, true), (forbidden.port, false)] {
        let url = format!("http://127.0.0.1:{port}/alpha/list");
        let args = ["-q", "-fsS", "--max-time", "2", &url];
        let command = PinnedCommand::new(
            Path::new("/usr/bin/curl"),
            &args.iter().map(std::ffi::OsStr::new).collect::<Vec<_>>(),
            Path::new(&request.cwd),
            &[("CURL_SSL_BACKEND".into(), "secure-transport".into())],
        )
        .unwrap();
        let result = command
            .capture(
                &[],
                8192,
                Instant::now() + Duration::from_secs(4),
                &AtomicBool::new(false),
                guard_contained_process::Isolation {
                    seatbelt: Some(profile.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            result.exit_code == Some(0),
            success,
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!result.timed_out, "kernel denial must complete, not hang");
    }
    assert_eq!(declared.seen.lock().unwrap().len(), 1);
    assert!(forbidden.seen.lock().unwrap().is_empty());
}

#[test]
fn bash_network_capture_refuses_unbound_config_and_deletion_before_effects() {
    let registry = Registry::start();
    let (_root, mut request) = tests::fixture();
    let helper = Path::new(&request.cwd).join("fixture-registry");
    std::fs::write(&helper, registry.helper()).unwrap();
    for name in [
        "http_proxy",
        "HTTPS_PROXY",
        "NO_PROXY",
        "CURL_CA_BUNDLE",
        "SSLKEYLOGFILE",
        "OPENSSL_CONF",
    ] {
        request
            .execution_environment
            .environment_names
            .push(name.into());
        assert!(
            matches!(inspect(&request), Err("bash_network_environment_unproven")),
            "{name}"
        );
        request.execution_environment.environment_names.pop();
    }
    request.command = request.command.trim_end_matches("dry").to_owned() + "delete";
    assert!(matches!(
        inspect(&request),
        Err("bash_network_read_delivery_unproven")
    ));
    assert!(registry.seen.lock().unwrap().is_empty());
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
}

#[test]
fn bash_http_backend_translation_preserves_plain_system_curl_response() {
    let registry = Registry::start();
    let (_root, request) = tests::fixture();
    std::fs::write(
        Path::new(&request.cwd).join("fixture-registry"),
        registry.helper(),
    )
    .unwrap();
    let captured = capture_for_launch(&request, &tests::admitted("allow")).unwrap();
    assert!(captured.policy.as_ref().unwrap().allows_without_consent());
    let url = format!("http://127.0.0.1:{}/alpha/list", registry.port);
    let run = |selected: bool| {
        let mut command = std::process::Command::new("/usr/bin/curl");
        command
            .args(["-q", "-fsS", "--max-time", "2", &url])
            .env_clear()
            .env("HOME", &request.home_dir)
            .env("LANG", "C");
        if selected {
            command.env("CURL_SSL_BACKEND", "secure-transport");
        }
        command.output().unwrap()
    };
    let original = run(false);
    let translated = run(true);
    assert!(original.status.success() && translated.status.success());
    assert_eq!(original.stdout, translated.stdout);
    assert_eq!(original.stderr, translated.stderr);
    assert_eq!(original.stdout, b"alpha/current\nalpha/obsolete\n");
    assert_eq!(registry.seen.lock().unwrap().len(), 2);
}
