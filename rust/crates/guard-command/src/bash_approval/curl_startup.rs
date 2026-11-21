//! The system curl's TLS library initializes even for a plain HTTP read.
//! Only dormant request-template sections are supported here: automatic
//! modules, provider/engine loading, includes and environment expansion need
//! separate analysis. For plain HTTP only, the owner may select the verified
//! OS TLS backend without changing request behavior; the dormant configuration
//! stays bound as an input and its live path stays unreadable during execution.

pub fn inert_openssl_config(source: &str) -> bool {
    if source.len() > 4096 || !source.is_ascii() || source.contains('\0') {
        return false;
    }
    let mut in_template = false;
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains(['$', '\\']) || line.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            return false;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if !matches!(
                section.trim(),
                "req" | "req_distinguished_name" | "req_attributes"
            ) {
                return false;
            }
            in_template = true;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim();
        if !in_template
            || key.is_empty()
            || key.starts_with('.')
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || !balanced_value(value)
        {
            return false;
        }
    }
    true
}

fn balanced_value(value: &str) -> bool {
    let mut quote = None;
    for byte in value.bytes() {
        match quote {
            Some(open) if byte == open => quote = None,
            Some(_) => (),
            None if byte == b'#' => break,
            None if matches!(byte, b'\'' | b'"') => quote = Some(byte),
            None => (),
        }
    }
    quote.is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn curl_startup_accepts_only_dormant_templates() {
        assert!(inert_openssl_config("# empty runtime config\n[ req ]\ndistinguished_name = req_distinguished_name\n[ req_distinguished_name ]\ncommonName = Example\n"));
        for input in [
            "openssl_conf = initialize\n",
            "[ default ]\nopenssl_conf=initialize\n",
            "[req]\n.include other.cnf\n",
            "[req]\n.include=other.cnf\n",
            "[req]\nvalue=$ENV::HOME\n",
            "[req]\nvalue=one\\\n.include other.cnf\n",
            "[engines]\nkey=value\n",
            "[providers]\nkey=value\n",
            "[req]\nengine=one\0\n",
            ";openssl_conf=initialize\n",
            "[req]\nvalue=\"unfinished\n",
            "[req]\nvalue='unfinished\n",
        ] {
            assert!(!inert_openssl_config(input), "{input:?}");
        }
    }
}
