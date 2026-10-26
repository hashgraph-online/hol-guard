use std::io::Cursor;

use serde_json::json;

use super::*;

fn lines(input: &[u8], limit: usize) -> Vec<Result<Vec<u8>, &'static str>> {
    let mut reader = Cursor::new(input.to_vec());
    let mut out = Vec::new();
    loop {
        match read_line(&mut reader, limit).unwrap() {
            Line::Bytes(bytes) => out.push(Ok(bytes)),
            Line::Eof => return out,
            Line::TooLong => {
                out.push(Err("too_long"));
                return out;
            }
        }
    }
}

fn drain(input: &[u8]) -> Vec<HostRead> {
    let (sender, receiver) = mpsc::sync_channel(64);
    pump(Cursor::new(input.to_vec()), &sender);
    drop(sender);
    receiver.iter().collect()
}

#[test]
fn read_line_splits_on_newlines_and_keeps_a_final_partial_line() {
    assert_eq!(
        lines(b"{}\n[1]\ntail", 64),
        vec![
            Ok(b"{}\n".to_vec()),
            Ok(b"[1]\n".to_vec()),
            Ok(b"tail".to_vec())
        ]
    );
    assert!(lines(b"", 64).is_empty());
}

#[test]
fn read_line_enforces_the_limit_including_the_newline() {
    assert_eq!(lines(b"abc\n", 4), vec![Ok(b"abc\n".to_vec())]);
    assert_eq!(lines(b"abcd\n", 4), vec![Err("too_long")]);
    assert_eq!(lines(b"abcde", 4), vec![Err("too_long")]);
}

#[test]
fn decode_keeps_the_argument_order_of_a_tools_call() {
    let call = br#"{"method":"tools/call","params":{"name":"x","arguments":{"z":1,"a":2}}}"#;
    let HostRead::Message(_, order) = decode(call) else {
        panic!("expected a message");
    };
    assert_eq!(order, Some(vec!["z".to_owned(), "a".to_owned()]));
    let single = br#"{"method":"tools/call","params":{"arguments":{"z":1}}}"#;
    assert!(matches!(decode(single), HostRead::Message(_, None)));
    let other = br#"{"method":"tools/list","params":{"arguments":{"z":1,"a":2}}}"#;
    assert!(matches!(decode(other), HostRead::Message(_, None)));
    let repeated = br#"{"method":"tools/call","params":{"arguments":{"z":1,"a":2,"z":3}}}"#;
    assert!(matches!(decode(repeated), HostRead::Message(_, None)));
}

#[test]
fn decode_accepts_only_json_objects() {
    assert_eq!(
        decode(b"{\"jsonrpc\":\"2.0\",\"id\":1}\n"),
        HostRead::Message(json!({"jsonrpc": "2.0", "id": 1}), None)
    );
    assert_eq!(
        decode(b"  {\"a\":1}  \r\n"),
        HostRead::Message(json!({"a": 1}), None)
    );
    assert_eq!(
        decode(b"[1]\n"),
        HostRead::Invalid("mcp_relay_host_message_not_object")
    );
    assert_eq!(
        decode(b"null"),
        HostRead::Invalid("mcp_relay_host_message_not_object")
    );
    assert_eq!(
        decode(b"{\"a\":\n"),
        HostRead::Invalid("mcp_relay_host_message_invalid")
    );
    assert_eq!(
        decode(b"\n"),
        HostRead::Invalid("mcp_relay_host_message_invalid")
    );
    assert_eq!(
        decode(b"\xff{}"),
        HostRead::Invalid("mcp_relay_host_message_invalid")
    );
}

#[test]
fn pump_forwards_messages_then_eof() {
    assert_eq!(
        drain(b"{\"id\":1}\n{\"id\":2}\n"),
        vec![
            HostRead::Message(json!({"id": 1}), None),
            HostRead::Message(json!({"id": 2}), None),
            HostRead::Eof,
        ]
    );
}

#[test]
fn pump_stops_at_the_first_invalid_line() {
    assert_eq!(
        drain(b"{\"id\":1}\nnot json\n{\"id\":2}\n"),
        vec![
            HostRead::Message(json!({"id": 1}), None),
            HostRead::Invalid("mcp_relay_host_message_invalid"),
        ]
    );
}

#[test]
fn pump_refuses_an_oversized_line() {
    let mut input = vec![b' '; HOST_LINE_LIMIT + 1];
    input.push(b'\n');
    assert_eq!(
        drain(&input),
        vec![HostRead::Invalid("mcp_relay_host_message_too_large")]
    );
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("boom"))
    }
}

#[test]
fn pump_reports_a_read_failure() {
    let (sender, receiver) = mpsc::sync_channel(4);
    pump(FailingReader, &sender);
    drop(sender);
    assert_eq!(
        receiver.iter().collect::<Vec<_>>(),
        vec![HostRead::Invalid("mcp_relay_host_read_failed")]
    );
}

#[test]
fn line_host_reads_messages_and_reports_eof_repeatedly() {
    let mut host = LineHost::spawn(Cursor::new(b"{\"id\":1}\n".to_vec()), Vec::new()).unwrap();
    assert_eq!(host.next(None), HostRead::Message(json!({"id": 1}), None));
    assert_eq!(host.next(Some(Duration::from_secs(5))), HostRead::Eof);
    assert_eq!(host.next(None), HostRead::Eof);
    assert_eq!(host.next(Some(Duration::from_millis(1))), HostRead::Eof);
}

struct Silent(mpsc::Receiver<()>);

impl Read for Silent {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        let _ = self.0.recv();
        Ok(0)
    }
}

#[test]
fn line_host_times_out_while_the_host_is_silent() {
    let (release, gate) = mpsc::channel();
    let mut host = LineHost::spawn(Silent(gate), Vec::new()).unwrap();
    assert_eq!(
        host.next(Some(Duration::from_millis(20))),
        HostRead::Timeout
    );
    release.send(()).unwrap();
    assert_eq!(host.next(Some(Duration::from_secs(5))), HostRead::Eof);
}

#[test]
fn line_host_writes_one_compact_line_per_message() {
    let mut host = LineHost::spawn(Cursor::new(Vec::new()), Vec::new()).unwrap();
    host.send(&json!({"jsonrpc": "2.0", "id": 1, "result": {"text": "é"}}))
        .unwrap();
    host.send(&json!({"jsonrpc": "2.0", "method": "notifications/progress"}))
        .unwrap();
    let written = String::from_utf8(host.output.clone()).unwrap();
    let frames: Vec<Value> = written
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(written.ends_with('\n'));
    assert_eq!(
        frames,
        vec![
            json!({"jsonrpc": "2.0", "id": 1, "result": {"text": "é"}}),
            json!({"jsonrpc": "2.0", "method": "notifications/progress"}),
        ]
    );
}

struct BrokenPipe;

impl Write for BrokenPipe {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn line_host_reports_a_write_failure() {
    let mut host = LineHost::spawn(Cursor::new(Vec::new()), BrokenPipe).unwrap();
    assert_eq!(
        host.send(&json!({"id": 1})).unwrap_err(),
        "mcp_relay_host_write_failed"
    );
}
