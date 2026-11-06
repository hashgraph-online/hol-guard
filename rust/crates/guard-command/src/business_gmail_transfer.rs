#![forbid(unsafe_code)]

//! Strict bounded decoding for the private single-part text profile. This does
//! not use a permissive MIME decoder that skips garbage or guesses an encoding.

use super::GmailPlainErrorV1 as Error;
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum TransferEncoding {
    SevenBit,
    EightBit,
    Base64,
    QuotedPrintable,
}

impl TransferEncoding {
    pub(super) fn from_header(value: &str) -> Result<Self, Error> {
        match value.to_ascii_lowercase().as_str() {
            "7bit" => Ok(Self::SevenBit),
            "8bit" => Ok(Self::EightBit),
            "base64" => Ok(Self::Base64),
            "quoted-printable" => Ok(Self::QuotedPrintable),
            _ => Err(Error::Unsupported),
        }
    }

    pub(super) fn decode(self, input: &[u8]) -> Result<Option<Box<[u8]>>, Error> {
        match self {
            Self::SevenBit | Self::EightBit => Ok(None),
            Self::Base64 => decode_base64(input).map(|b| Some(b.into_boxed_slice())),
            Self::QuotedPrintable => {
                decode_quoted_printable(input).map(|b| Some(b.into_boxed_slice()))
            }
        }
    }
}

fn encoded_lines(input: &[u8]) -> Result<Vec<&[u8]>, Error> {
    for (index, byte) in input.iter().enumerate() {
        if (*byte == b'\r' && input.get(index + 1) != Some(&b'\n'))
            || (*byte == b'\n' && (index == 0 || input[index - 1] != b'\r'))
        {
            return Err(Error::Invalid);
        }
    }
    let lines: Vec<_> = input
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect();
    if lines.iter().any(|line| line.len() > 76) {
        return Err(Error::BoundsExceeded);
    }
    Ok(lines)
}

fn decode_base64(input: &[u8]) -> Result<Vec<u8>, Error> {
    let lines = encoded_lines(input)?;
    let mut compact = Vec::with_capacity(input.len());
    for (index, line) in lines.iter().enumerate() {
        if (line.is_empty() && index + 1 != lines.len())
            || line.len() % 4 != 0
            || !line
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err(Error::Invalid);
        }
        compact.extend_from_slice(line);
    }
    let decoded = STANDARD.decode(&compact).map_err(|_| Error::Invalid)?;
    if STANDARD.encode(&decoded).as_bytes() != compact {
        return Err(Error::Invalid);
    }
    Ok(decoded)
}

fn uppercase_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_quoted_printable(input: &[u8]) -> Result<Vec<u8>, Error> {
    if encoded_lines(input)?
        .iter()
        .any(|line| matches!(line.last(), Some(b' ' | b'\t')))
    {
        return Err(Error::Invalid);
    }
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'=' if input.get(index + 1..index + 3) == Some(b"\r\n") => index += 3,
            b'=' => {
                let high = input
                    .get(index + 1)
                    .and_then(|b| uppercase_hex(*b))
                    .ok_or(Error::Invalid)?;
                let low = input
                    .get(index + 2)
                    .and_then(|b| uppercase_hex(*b))
                    .ok_or(Error::Invalid)?;
                output.push(high * 16 + low);
                index += 3;
            }
            byte if matches!(byte, b'\r' | b'\n' | b'\t' | b' ' | 33..=60 | 62..=126) => {
                output.push(byte);
                index += 1;
            }
            _ => return Err(Error::Invalid),
        }
    }
    Ok(output)
}
