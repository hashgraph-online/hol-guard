//! Fixed-operation transport results. An API acknowledgement is not delivery
//! confirmation. Transport never supplies native policy or approval authority.

pub(crate) const GMAIL_SEND_URL: &str =
    "https://gmail.googleapis.com/gmail/v1/users/me/messages/send?fields=id%2CthreadId";

#[derive(Debug, PartialEq, Eq)]
pub enum GoogleDispatchError {
    Expired,
    InputChanged,
    WrongPurpose,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GoogleSendAttempt {
    ApiAccepted { message_binding: String },
    // The request might have taken effect. Never automatically retry it.
    Unconfirmed,
}

pub(crate) struct Acknowledgement {
    pub(crate) id: zeroize::Zeroizing<String>,
    pub(crate) thread_id: zeroize::Zeroizing<String>,
}
pub(crate) enum RawSendAttempt {
    Accepted(Acknowledgement),
    Unconfirmed,
}
