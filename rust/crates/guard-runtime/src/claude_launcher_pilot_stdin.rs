//! Match the frozen Python UTF-8/surrogateescape stdin character ceiling.
//! A writer that holds a shorter input open still needs outer containment.
use std::io::{self, BufRead};

const CHARACTER_LIMIT: usize = 1_000_001;

fn consume_text(text: &str, offset: &mut usize, characters: &mut usize) -> Option<usize> {
    let remaining = CHARACTER_LIMIT - *characters;
    if text.is_ascii() {
        if text.len() >= remaining {
            return Some(*offset + remaining);
        }
        *characters += text.len();
    } else {
        let count = text.chars().count();
        if count >= remaining {
            return Some(
                *offset
                    + text
                        .char_indices()
                        .nth(remaining)
                        .map_or(text.len(), |(index, _)| index),
            );
        }
        *characters += count;
    }
    *offset += text.len();
    None
}

fn consumed_end(
    raw: &[u8],
    offset: &mut usize,
    characters: &mut usize,
    eof: bool,
) -> Option<usize> {
    loop {
        match std::str::from_utf8(&raw[*offset..]) {
            Ok(text) => return consume_text(text, offset, characters),
            Err(error) => {
                let valid = error.valid_up_to();
                let text = std::str::from_utf8(&raw[*offset..*offset + valid])
                    .expect("validated UTF-8 prefix");
                if let Some(end) = consume_text(text, offset, characters) {
                    return Some(end);
                }
                let invalid = match error.error_len() {
                    Some(length) => length,
                    None if eof => raw.len() - *offset,
                    None => return None,
                };
                // Python surrogateescape maps each undecodable byte to one
                // character. Preserve its exact byte prefix for Python handoff.
                if *characters + invalid >= CHARACTER_LIMIT {
                    return Some(*offset + CHARACTER_LIMIT - *characters);
                }
                *characters += invalid;
                *offset += invalid;
            }
        }
    }
}

pub(super) fn read(mut input: impl BufRead) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    let (mut offset, mut characters) = (0, 0);
    loop {
        let chunk = match input.fill_buf() {
            Ok(chunk) => chunk,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let eof = chunk.is_empty();
        let length = chunk.len().min(8192);
        raw.extend_from_slice(&chunk[..length]);
        input.consume(length);
        if let Some(end) = consumed_end(&raw, &mut offset, &mut characters, eof) {
            raw.truncate(end);
            return Ok(raw);
        }
        if eof {
            return Ok(raw);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    struct HeldWriter {
        bytes: std::io::Cursor<Vec<u8>>,
    }
    impl io::Read for HeldWriter {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = io::Read::read(&mut self.bytes, buffer)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "writer remains open",
                ));
            }
            Ok(count)
        }
    }

    #[test]
    fn reaches_character_limit_without_waiting_for_eof() {
        for character in ["a", "é", "🚀"] {
            let expected = character.repeat(CHARACTER_LIMIT).into_bytes();
            let mut supplied = expected.clone();
            supplied.extend_from_slice(b"unread suffix");
            assert_eq!(
                read(BufReader::with_capacity(
                    4093,
                    HeldWriter {
                        bytes: std::io::Cursor::new(supplied)
                    }
                ))
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn invalid_and_incomplete_utf8_preserves_surrogateescape_character_count() {
        for invalid in [&b"\xff"[..], &b"\xe2\x82"[..], &b"\xf0\x90\x80"[..]] {
            let mut supplied = vec![b'a'; CHARACTER_LIMIT - invalid.len()];
            supplied.extend_from_slice(invalid);
            assert_eq!(
                read(std::io::Cursor::new(supplied.clone())).unwrap(),
                supplied
            );
        }
        let mut supplied = vec![b'a'; CHARACTER_LIMIT - 1];
        supplied.extend_from_slice(b"\xffunread");
        assert_eq!(
            read(BufReader::new(HeldWriter {
                bytes: std::io::Cursor::new(supplied)
            }))
            .unwrap()
            .len(),
            CHARACTER_LIMIT
        );
    }
}
