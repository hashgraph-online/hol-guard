//! The DER the trust attestation key loader reads by hand: a SEC1 key wrapped
//! as PKCS#8 for ring, and the named curve of an EC key ring cannot read.

use zeroize::Zeroizing;

use super::{PrivateKey, EC_PUBLIC_KEY_OID, KEY_UNREADABLE, P256_OID};

/// The named-curve arcs Python's loader reads beyond P-256 and P-384: SEC 2
/// (`1.3.132.0`), X9.62 prime curves (`1.2.840.10045.3.1`) and Brainpool.
const OTHER_CURVE_ARCS: [&[u8]; 3] = [
    &[0x2b, 0x81, 0x04, 0x00],
    &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01],
    &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01],
];

/// An EC key ring cannot read, on a named curve other than P-256. A P-256 key
/// ring refuses (one without its public key) stays unreadable.
pub(super) fn other_curve(curve: Option<&[u8]>) -> Result<PrivateKey, &'static str> {
    let named = curve.and_then(der_element).and_then(|(tag, oid, rest)| {
        (tag == 0x06 && rest.is_empty())
            .then(|| OTHER_CURVE_ARCS.iter().any(|arc| oid.starts_with(arc)))
    });
    match curve {
        Some(curve) if named == Some(true) && curve != &P256_OID[..] => {
            Ok(PrivateKey::UnsupportedCurve)
        }
        _ => Err(KEY_UNREADABLE),
    }
}

/// The curve parameter of an EC PKCS#8 document.
pub(super) fn pkcs8_curve(der: &[u8]) -> Option<&[u8]> {
    let Some((0x30, document, _)) = der_element(der) else {
        return None;
    };
    let Some((0x02, _, rest)) = der_element(document) else {
        return None;
    };
    let Some((0x30, algorithm, _)) = der_element(rest) else {
        return None;
    };
    algorithm.strip_prefix(&EC_PUBLIC_KEY_OID[..])
}

/// The `[0]` curve parameter of a SEC1 `ECPrivateKey`.
pub(super) fn sec1_curve(der: &[u8]) -> Option<&[u8]> {
    let Some((0x30, key, _)) = der_element(der) else {
        return None;
    };
    let Some((0x02, _, rest)) = der_element(key) else {
        return None;
    };
    let Some((0x04, _, rest)) = der_element(rest) else {
        return None;
    };
    let Some((0xa0, parameters, _)) = der_element(rest) else {
        return None;
    };
    Some(parameters)
}

/// One DER element of `bytes`: its tag, its content and what follows it.
fn der_element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let (octets, rest) = rest.split_at_checked(usize::from(first & 0x7f))?;
        if octets.is_empty() || octets.len() > 4 {
            return None;
        }
        let length = octets
            .iter()
            .fold(0_usize, |length, octet| (length << 8) | usize::from(*octet));
        (length, rest)
    };
    let (content, rest) = rest.split_at_checked(length)?;
    Some((tag, content, rest))
}

/// A SEC1 `ECPrivateKey` wrapped as the PKCS#8 document of `curve`; ring
/// reads only PKCS#8 and rejects the document when its curve differs.
pub(super) fn sec1_as_pkcs8(sec1: &[u8], curve: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut algorithm = EC_PUBLIC_KEY_OID.to_vec();
    algorithm.extend_from_slice(curve);
    let mut body = Zeroizing::new(vec![0x02, 0x01, 0x00]);
    push_der(&mut body, 0x30, &algorithm);
    push_der(&mut body, 0x04, sec1);
    let mut document = Zeroizing::new(Vec::new());
    push_der(&mut document, 0x30, &body);
    document
}

fn push_der(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    let length = content.len().to_be_bytes();
    let skip = length.iter().take_while(|byte| **byte == 0).count();
    match u8::try_from(content.len()) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            // At most eight length octets, so the count fits the low bits.
            out.push(0x80 | u8::try_from(length.len() - skip).unwrap_or(0));
            out.extend_from_slice(&length[skip..]);
        }
    }
    out.extend_from_slice(content);
}
