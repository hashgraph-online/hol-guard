//! Explicit experimental text-facts helper; it carries no policy authority.
//!
//! The parent supplies the exact Python-normalized private text. Requests are
//! MFT1 + big-endian u64 sequence + big-endian u32 UTF-8 byte length + body.
//! Responses are MFR1 + the same sequence + one byte of predicate flags.
//! No input text is serialized again, normalized, logged, or written to disk.

use regex::{RegexSet, RegexSetBuilder};
use std::io::{self, ErrorKind, Read, Write};
use std::process::ExitCode;

const HEADER_BYTES: usize = 16;
const MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;
const MAX_BODY_BYTES: usize = MAX_PACKET_BYTES - HEADER_BYTES;
const REGEX_SIZE_LIMIT: usize = 2 * 1024 * 1024;
const FLAGS: [u8; 13] = [1, 1, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 8];

// Python str regex \s includes U+001C..U+001F, unlike Rust's default \s.
const PYTHON_WHITESPACE: &str = r"[\x09-\x0d\x1c-\x20\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]";

// These are the 13 fixed predicates from _tool_call_risk_category_set.
// Consuming ASCII boundary alternatives preserve boolean-match existence;
// this helper never returns offsets or match counts that consume boundaries.
const PATTERNS: [&str; 13] = [
    r"(?:^|[^a-z0-9_])(subprocess|child_process|childprocess|popen|os\.system|runtime\.exec)(?:$|[^a-z0-9_])",
    r"(?:^|[^a-z0-9_])(spawn|execfile|system)(?:_sync)?\s*\(",
    r"(http://|https://)",
    r"(?:^|[^a-z0-9])(curl|wget|fetch|axios|requests)(?:$|[^a-z0-9])",
    r"(?:^|[^a-z0-9_])(socket|net|dns)\s*[.(]",
    r"(?:^|[^a-z0-9_])(create_connection|getaddrinfo|gethostbyname|sendto|recvfrom)\s*\(",
    r"(?:^|[^a-z0-9_])(urllib\.request|urllib|http\.client|http|https)\s*\.",
    r"(?:^|[^a-z0-9_])(udp|tcp|socks|proxy|tunnel|port_forward|port\-forward)(?:$|[^a-z0-9_])",
    r"(?:^|[^a-z0-9_-])(\.env)(?:$|[^a-z0-9_-])",
    r"(?:^|[^a-z0-9_-])(\.ssh)(?:$|[^a-z0-9_-])",
    r"(?:^|[^a-z0-9])(idrsa|id_rsa|id\-rsa|credentials|token|secret|passwd)(?:$|[^a-z0-9])",
    r"(?:^|[^a-z0-9_-])(\.npmrc|\.pypirc)(?:$|[^a-z0-9_-])",
    r"(?:^|[^a-z0-9])(sudo|chmod|chown|launchctl|systemctl)(?:$|[^a-z0-9])",
];

#[derive(Debug, PartialEq, Eq)]
enum Failure {
    Read,
    PartialHeader,
    PartialBody,
    Magic,
    Sequence,
    Length,
    Allocation,
    Utf8,
    Regex,
    Write,
}

fn compile_predicates() -> Result<RegexSet, Failure> {
    let patterns = PATTERNS.map(|pattern| pattern.replace(r"\s", PYTHON_WHITESPACE));
    RegexSetBuilder::new(patterns)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|_| Failure::Regex)
}

fn classify(predicates: &RegexSet, text: &str) -> u8 {
    predicates
        .matches(text)
        .into_iter()
        .fold(0, |flags, index| flags | FLAGS[index])
}

fn read_request<R: Read>(reader: &mut R, previous: u64) -> Result<Option<(u64, Vec<u8>)>, Failure> {
    let mut header = [0_u8; HEADER_BYTES];
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(Failure::Read),
        }
    }
    reader.read_exact(&mut header[1..]).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            Failure::PartialHeader
        } else {
            Failure::Read
        }
    })?;
    if &header[..4] != b"MFT1" {
        return Err(Failure::Magic);
    }
    let sequence = u64::from_be_bytes(header[4..12].try_into().map_err(|_| Failure::Sequence)?);
    if sequence == 0 || sequence <= previous {
        return Err(Failure::Sequence);
    }
    let length =
        u32::from_be_bytes(header[12..16].try_into().map_err(|_| Failure::Length)?) as usize;
    if length > MAX_BODY_BYTES {
        return Err(Failure::Length);
    }
    // Reject the advertised packet limit before allocating or reading a body.
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| Failure::Allocation)?;
    body.resize(length, 0);
    reader.read_exact(&mut body).map_err(|error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            Failure::PartialBody
        } else {
            Failure::Read
        }
    })?;
    Ok(Some((sequence, body)))
}

fn run<R: Read, W: Write>(mut reader: R, mut writer: W) -> Result<(), Failure> {
    let predicates = compile_predicates()?;
    let mut previous = 0;
    while let Some((sequence, body)) = read_request(&mut reader, previous)? {
        let text = std::str::from_utf8(&body).map_err(|_| Failure::Utf8)?;
        let mut response = [0_u8; 13];
        response[..4].copy_from_slice(b"MFR1");
        response[4..12].copy_from_slice(&sequence.to_be_bytes());
        response[12] = classify(&predicates, text);
        writer.write_all(&response).map_err(|_| Failure::Write)?;
        writer.flush().map_err(|_| Failure::Write)?;
        previous = sequence;
    }
    Ok(())
}

fn main() -> ExitCode {
    if run(io::stdin().lock(), io::stdout().lock()).is_ok() {
        ExitCode::SUCCESS
    } else {
        // A failed private request produces only a nonzero status, no payload.
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn frame(sequence: u64, body: &[u8]) -> Vec<u8> {
        let mut packet = b"MFT1".to_vec();
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn fixed_predicates_preserve_ascii_boundaries_and_boolean_groups() {
        let predicates = compile_predicates().unwrap();
        for (text, expected) in [
            (
                "subprocess child_process childprocess popen os.system runtime.exec",
                1,
            ),
            ("spawn( execfile_sync ( system (", 1),
            (
                "safe_subprocess_name childprocesses safe_spawn( systems(",
                0,
            ),
            ("http://example.invalid https://example.invalid", 2),
            ("curl wget fetch axios requests", 2),
            ("_curl_", 2),
            ("socket. net( dns .", 2),
            (
                "create_connection( getaddrinfo ( gethostbyname( sendto( recvfrom(",
                2,
            ),
            ("urllib.request. urllib . http.client. http. https .", 2),
            ("udp tcp socks proxy tunnel port_forward port-forward", 2),
            ("curly safe_socket. safe_http. proxy_name", 0),
            (".env .ssh .npmrc .pypirc", 4),
            ("idrsa id_rsa id-rsa credentials token secret passwd", 4),
            ("_token_ .env.local ~/.ssh/id_rsa", 4),
            ("foo.env .env-prod .env_foo tokenized secret1", 0),
            ("sudo chmod chown launchctl systemctl", 8),
            ("_sudo_", 8),
            ("presudo sudos", 0),
            ("αsubprocessβ", 1),
            ("subprocess curl secret sudo", 15),
            ("SUBPROCESS CURL SECRET SUDO", 0),
            ("", 0),
        ] {
            assert_eq!(classify(&predicates, text), expected, "{text:?}");
        }
    }

    #[test]
    fn python_whitespace_is_explicit_and_no_text_normalization_occurs() {
        let predicates = compile_predicates().unwrap();
        for value in (0x09..=0x0d)
            .chain(0x1c..=0x20)
            .chain([0x85, 0xa0, 0x1680])
            .chain(0x2000..=0x200a)
            .chain([0x2028, 0x2029, 0x202f, 0x205f, 0x3000])
        {
            let whitespace = char::from_u32(value).unwrap();
            assert_eq!(classify(&predicates, &format!("spawn{whitespace}(")), 1);
            assert_eq!(classify(&predicates, &format!("socket{whitespace}.")), 2);
        }
        for other in ['\0', '\u{180e}', '\u{200b}', '\u{feff}'] {
            assert_eq!(classify(&predicates, &format!("spawn{other}(")), 0);
            assert_eq!(classify(&predicates, &format!("net{other}.")), 0);
        }
    }

    #[test]
    fn empty_input_and_repeated_complete_frames_have_exact_responses() {
        let mut output = Vec::new();
        assert_eq!(run(Cursor::new([]), &mut output), Ok(()));
        assert!(output.is_empty());
        let mut input = frame(1, b"subprocess");
        input.extend(frame(4, b"curl .env sudo"));
        input.extend(frame(u64::MAX, b""));
        assert_eq!(run(Cursor::new(input), &mut output), Ok(()));
        assert_eq!(output.len(), 39);
        for (response, sequence, flags) in [
            (&output[..13], 1_u64, 1),
            (&output[13..26], 4, 14),
            (&output[26..], u64::MAX, 0),
        ] {
            assert_eq!(&response[..4], b"MFR1");
            assert_eq!(&response[4..12], &sequence.to_be_bytes());
            assert_eq!(response[12], flags);
        }
    }

    #[test]
    fn partial_invalid_and_non_increasing_frames_fail_without_a_reply() {
        let complete = frame(1, b"body");
        for length in 1..HEADER_BYTES {
            let mut output = Vec::new();
            assert_eq!(
                run(Cursor::new(&complete[..length]), &mut output),
                Err(Failure::PartialHeader)
            );
            assert!(output.is_empty());
        }
        for (packet, expected) in [
            (
                complete[..complete.len() - 1].to_vec(),
                Failure::PartialBody,
            ),
            (frame(1, &[0xff]), Failure::Utf8),
            (frame(0, b"private"), Failure::Sequence),
            (
                {
                    let mut packet = frame(1, b"private");
                    packet[0] = b'X';
                    packet
                },
                Failure::Magic,
            ),
        ] {
            let mut output = Vec::new();
            assert_eq!(run(Cursor::new(packet), &mut output), Err(expected));
            assert!(output.is_empty());
        }
        for next in [0, 1, 2] {
            let mut input = frame(2, b"safe");
            input.extend(frame(next, b"private"));
            let mut output = Vec::new();
            assert_eq!(run(Cursor::new(input), &mut output), Err(Failure::Sequence));
            assert_eq!(output.len(), 13);
            assert_eq!(output[12], 0);
        }
    }

    #[test]
    fn whole_packet_byte_limit_includes_the_header() {
        let mut header = frame(1, b"");
        header[12..16].copy_from_slice(&((MAX_BODY_BYTES + 1) as u32).to_be_bytes());
        assert_eq!(
            read_request(&mut Cursor::new(header), 0),
            Err(Failure::Length)
        );
        let input = frame(1, &vec![b'x'; MAX_BODY_BYTES]);
        assert_eq!(input.len(), MAX_PACKET_BYTES);
        let mut output = Vec::new();
        assert_eq!(run(Cursor::new(input), &mut output), Ok(()));
        assert_eq!(output.len(), 13);
        assert_eq!(output[12], 0);
    }

    #[test]
    fn failed_output_is_not_retried_or_reported_as_a_complete_request() {
        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("a failed write must terminate before flush");
            }
        }
        assert_eq!(
            run(Cursor::new(frame(1, b"safe")), BrokenWriter),
            Err(Failure::Write)
        );
    }
}
