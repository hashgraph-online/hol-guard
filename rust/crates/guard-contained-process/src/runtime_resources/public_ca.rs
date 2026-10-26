use super::*;

/// Only these package-owned names are eligible for a public certificate bundle.
/// The capture owner still enforces its approved installation roots and budget.
pub(super) fn public_ca_bundle(path: &Path) -> bool {
    let parts: Vec<_> = path
        .components()
        .map(|part| part.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    let Some(index) = parts
        .iter()
        .rposition(|part| part == "site-packages" || part == "dist-packages")
    else {
        return false;
    };
    let tail: Vec<_> = parts[index + 1..].iter().map(String::as_str).collect();
    matches!(
        tail.as_slice(),
        ["certifi", "cacert.pem"]
            | ["pip", "_vendor", "certifi", "cacert.pem"]
            | ["botocore", "cacert.pem"]
    )
}

pub(super) fn resource_protected(path: &Path) -> bool {
    if public_ca_bundle(path) {
        // A public filename never makes a protected parent traversable.
        return path.parent().is_none_or(super::protected);
    }
    super::protected(path)
}

/// Validate certificate-only PEM framing, not certificate trust or validity.
/// Private-key blocks, mixed bundles and unframed content remain rejected.
pub(super) fn certificate_envelopes(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut inside = false;
    let mut payload = false;
    let mut certificates = 0usize;
    for line in text.lines().map(str::trim) {
        match line {
            "-----BEGIN CERTIFICATE-----" if !inside => {
                inside = true;
                payload = false;
            }
            "-----END CERTIFICATE-----" if inside && payload => {
                inside = false;
                certificates += 1;
            }
            "" => {}
            value if !inside && value.starts_with('#') => {}
            value
                if inside
                    && value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
                    }) =>
            {
                payload = true;
            }
            _ => return false,
        }
    }
    !inside && certificates > 0
}
