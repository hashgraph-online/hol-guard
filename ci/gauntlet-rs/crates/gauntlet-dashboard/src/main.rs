use gauntlet_dashboard::{http, snapshot::PublicRoot};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

fn healthcheck(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut connection = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    connection.set_read_timeout(Some(Duration::from_secs(2)))?;
    connection.set_write_timeout(Some(Duration::from_secs(2)))?;
    connection.write_all(b"GET /healthz HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")?;
    let mut response = Vec::new();
    connection.take(4097).read_to_end(&mut response)?;
    if response.len() > 4096 {
        return Err("Rust dashboard health response exceeded limit".into());
    }
    let (headers, body) = response.split_at(
        response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or("Rust dashboard health response omitted headers")?
            + 4,
    );
    let headers = std::str::from_utf8(headers)?;
    if !headers.starts_with("HTTP/1.1 200 OK\r\n")
        || !headers.contains("\r\nContent-Type: application/json\r\n")
    {
        return Err("Rust dashboard health endpoint did not identify JSON service".into());
    }
    let health: Value = serde_json::from_slice(body)?;
    let instance = match health.get("instance_id") {
        Some(Value::Null) => true,
        Some(Value::String(id)) => {
            id.len() == 32
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }
        _ => false,
    };
    if health.get("service").and_then(Value::as_str) != Some("hol-gauntlet-dashboard")
        || health.get("server").and_then(Value::as_str) != Some("online")
        || !instance
    {
        return Err("Rust dashboard identity differs from Gauntlet".into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--healthcheck")
    {
        let port = match arguments.len() {
            1 => 8787,
            3 if arguments[1] == "--port" => arguments[2].parse::<u16>()?,
            _ => return Err("healthcheck accepts only optional --port PORT".into()),
        };
        return healthcheck(port);
    }
    let mut args = arguments.into_iter();
    let mut state = None;
    let mut port = 8792u16;
    let mut bind = Ipv4Addr::LOCALHOST;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--state" => state = args.next().map(PathBuf::from),
            "--port" => port = args.next().ok_or("--port needs a value")?.parse()?,
            "--bind" => {
                bind = match args.next().as_deref() {
                    Some("127.0.0.1") => Ipv4Addr::LOCALHOST,
                    Some("0.0.0.0") => Ipv4Addr::UNSPECIFIED,
                    _ => return Err("--bind accepts only 127.0.0.1 or 0.0.0.0".into()),
                }
            }
            _ => return Err(format!("unknown argument: {arg}").into()),
        }
    }
    let state = state.ok_or("--state requires an absolute public directory")?;
    if !state.is_absolute() {
        return Err("--state requires an absolute public directory".into());
    }
    let root = PublicRoot::open(&state)?;
    let listener = TcpListener::bind((bind, port))?;
    println!("Gauntlet Rust dashboard listening on {bind}:{port}");
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if let Err(error) = http::handle(stream, &root) {
                    eprintln!("dashboard request failed: {error}");
                }
            }
            Err(error) => eprintln!("dashboard connection failed: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn fake_service(body: &'static str) -> bool {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 128];
            let count = stream.read(&mut request).unwrap();
            assert!(request[..count].starts_with(b"GET /healthz"));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let accepted = healthcheck(port).is_ok();
        server.join().unwrap();
        accepted
    }

    #[test]
    fn healthcheck_accepts_only_gauntlet_instance_not_other_local_200() {
        assert!(!fake_service(
            r#"{"service":"torch","instance_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","server":"online"}"#
        ));
        assert!(fake_service(
            r#"{"service":"hol-gauntlet-dashboard","instance_id":null,"server":"online"}"#
        ));
        assert!(!fake_service(
            r#"{"service":"hol-gauntlet-dashboard","instance_id":"invalid","server":"online"}"#
        ));
        assert!(fake_service(
            r#"{"service":"hol-gauntlet-dashboard","instance_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","server":"online"}"#
        ));
    }
}
