//! Private signed mailbox evidence. Account identity continues to use `sub`
//! and tenant identity uses `hd`; a mailbox is never an enrollment authority.

use zeroize::Zeroizing;

pub(super) struct VerifiedSender(Zeroizing<String>);

impl VerifiedSender {
    pub(super) fn from_claims(email: Option<String>, verified: Option<bool>) -> Option<Self> {
        let email = Zeroizing::new(email?);
        if verified != Some(true) || !supported_mailbox(&email) {
            return None;
        }
        Some(Self(email))
    }

    pub(super) fn matches(&self, sender: &str) -> bool {
        // No case folding, alias expansion or Gmail dot/plus normalization.
        // False negatives are safe; send-as aliases need separate authority.
        self.0.as_str() == sender
    }
}

fn supported_mailbox(email: &str) -> bool {
    if email.len() > 254 || !email.is_ascii() {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
        && domain.contains('.')
        && guard_contracts::is_canonical_business_domain(domain)
}
