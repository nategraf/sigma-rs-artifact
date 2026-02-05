use thiserror::Error;

/// This error is thrown if the number of buckets/keys in the bridge table
/// exceeds u32 MAX.It is unlikely this error will ever occur.
#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("time threshold for operation will not be met for {0} more days")]
    TimeThresholdNotMet(u32),
    #[error("credential has expired")]
    CredentialExpired,
    #[error("invalid field {0}: {1}")]
    InvalidField(String, String),
    #[error("exceeded blockages threshold")]
    ExceededBlockagesThreshold,
    #[error("credential has no available invitations")]
    NoInvitationsRemaining,
    #[error("supplied credentials do not match")]
    CredentialMismatch,
}
