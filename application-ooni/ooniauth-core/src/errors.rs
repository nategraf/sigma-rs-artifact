use thiserror::Error;

/// Credential errors that can be encountered by the client or server
#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("time threshold for operation will not be met for {0} more days")]
    TimeThresholdNotMet(u32),
    #[error("credential has expired")]
    CredentialExpired,
    #[error("invalid field {0}: {1}")]
    InvalidField(String, String),
    #[error("supplied credentials do not match")]
    CredentialMismatch,
    #[error("CMZ Error")]
    CMZError(cmz::CMZError),
}
